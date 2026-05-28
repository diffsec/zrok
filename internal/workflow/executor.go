package workflow

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"golang.org/x/sync/errgroup"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/agentloop/tools"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/store"
)

// AgentLookup returns the AgentConfig for a name. Defaults to the
// built-in registry when nil.
type AgentLookup func(name string) (*agent.AgentConfig, error)

// ProviderFactory builds an llm.Provider for the given per-agent model
// config (nil means "use org defaults").
type ProviderFactory func(modelCfg *agent.ModelConfig) (llm.Provider, error)

// Executor drives a Workflow to completion against a fixed set of stores,
// a tool registry, and a Provider factory.
type Executor struct {
	Stores          *store.Stores
	ToolRegistry    *tools.Registry
	ProviderFactory ProviderFactory
	AgentLookup     AgentLookup
	Sink            agentloop.EventSink
	Project         *project.Project
	Classification  project.ProjectClassification

	// SpawnDefaults are propagated into child specs (max iters, max
	// tokens, etc.). Zero values use the loop's built-in defaults.
	SpawnDefaults tools.SpawnDefaults
}

// Run drives every phase to completion in declaration order. Returns the
// first phase-level error encountered.
func (e *Executor) Run(ctx context.Context, w *Workflow, rc RunContext) error {
	if e == nil {
		return fmt.Errorf("workflow: nil executor")
	}
	if w == nil {
		return fmt.Errorf("workflow: nil workflow")
	}
	lookup := e.AgentLookup
	if lookup == nil {
		lookup = defaultAgentLookup
	}
	if e.ProviderFactory == nil {
		return fmt.Errorf("workflow: provider factory not set")
	}
	registry := e.ToolRegistry
	if registry == nil {
		registry = tools.Default()
	}

	findingObserver := &findingObserver{}

	for _, phase := range w.Phases {
		applicable, skipped := e.filterAgents(phase.Agents, lookup)
		for _, name := range skipped {
			e.emit(agentloop.TranscriptEvent{
				Kind:    agentloop.KindAgentStart,
				Payload: map[string]string{"agent": name, "skipped": "applicability_mismatch"},
			})
		}
		hook, perFinding, err := renderHook(phase, rc, findingObserver.snapshot())
		if err != nil {
			return fmt.Errorf("phase %q: render hook: %w", phase.Name, err)
		}
		if err := e.runPhase(ctx, phase, applicable, lookup, registry, hook, perFinding, rc, findingObserver); err != nil {
			return err
		}
	}
	return nil
}

func (e *Executor) emit(ev agentloop.TranscriptEvent) {
	if e.Sink == nil {
		return
	}
	e.Sink.Emit(ev)
}

// filterAgents partitions the phase's agent list into (applicable,
// skipped) by ApplicabilityMatches.
func (e *Executor) filterAgents(names []string, lookup AgentLookup) (applicable, skipped []string) {
	for _, n := range names {
		cfg, err := lookup(n)
		if err != nil || cfg == nil {
			skipped = append(skipped, n)
			continue
		}
		if !project.ApplicabilityMatches(cfg.Applicability, e.Classification) {
			skipped = append(skipped, n)
			continue
		}
		applicable = append(applicable, n)
	}
	return
}

// runPhase runs the agents in the phase per the phase's mode.
func (e *Executor) runPhase(
	ctx context.Context,
	phase Phase,
	agents []string,
	lookup AgentLookup,
	registry *tools.Registry,
	hook string,
	perFinding []perFindingExpansion,
	rc RunContext,
	obs *findingObserver,
) error {
	if len(perFinding) > 0 {
		return e.runPerFinding(ctx, phase, perFinding, lookup, registry, rc, obs)
	}
	switch phase.Mode {
	case ModeSequential, "":
		for _, name := range agents {
			if err := e.runOneAgent(ctx, name, lookup, registry, hook, rc, obs); err != nil {
				return err
			}
		}
		return nil
	case ModeParallel:
		max := phase.MaxParallel
		if max <= 0 {
			max = 4
		}
		sem := make(chan struct{}, max)
		g, gctx := errgroup.WithContext(ctx)
		for _, name := range agents {
			name := name
			g.Go(func() error {
				select {
				case sem <- struct{}{}:
				case <-gctx.Done():
					return gctx.Err()
				}
				defer func() { <-sem }()
				return e.runOneAgent(gctx, name, lookup, registry, hook, rc, obs)
			})
		}
		return g.Wait()
	default:
		return fmt.Errorf("phase %q: unknown mode %q", phase.Name, phase.Mode)
	}
}

func (e *Executor) runOneAgent(
	ctx context.Context,
	name string,
	lookup AgentLookup,
	registry *tools.Registry,
	hook string,
	rc RunContext,
	obs *findingObserver,
) error {
	cfg, err := lookup(name)
	if err != nil {
		return fmt.Errorf("agent %q: lookup: %w", name, err)
	}
	provider, err := e.ProviderFactory(cfg.ModelConfig)
	if err != nil {
		return fmt.Errorf("agent %q: provider: %w", name, err)
	}

	// Use PromptGenerator to assemble the system prompt with the hook
	// and changed files appended; tools are filtered by ToolsAllowed.
	gen := agent.NewPromptGenerator(e.Project, nil)
	system, _, toolSpecs, err := gen.GenerateWithToolSpecs(cfg, hook, rc.ChangedFiles, registry)
	if err != nil {
		return fmt.Errorf("agent %q: prompt: %w", name, err)
	}

	model := ""
	temp := float32(0)
	maxTokens := 0
	if cfg.ModelConfig != nil {
		model = cfg.ModelConfig.Model
		temp = cfg.ModelConfig.Temperature
		maxTokens = cfg.ModelConfig.MaxTokens
	}

	env := &tools.Env{
		Project:         e.Project,
		Stores:          e.Stores,
		AgentName:       cfg.Name,
		RepoID:          rc.RepoID,
		RunID:           rc.RunID,
		CreatedBy:       cfg.Name,
		AgentLookup:     func(n string) (*agent.AgentConfig, error) { return lookup(n) },
		ProviderFactory: func(mc *agent.ModelConfig) (llm.Provider, error) { return e.ProviderFactory(mc) },
		SpawnDefaults:   e.SpawnDefaults,
		FindingSink:     obs,
	}

	_, err = agentloop.Run(ctx, agentloop.Spec{
		RunID:        rc.RunID,
		AgentName:    cfg.Name,
		Provider:     provider,
		Model:        model,
		Temperature:  temp,
		MaxTokens:    maxTokens,
		SystemPrompt: system,
		Tools:        toolSpecs,
		ToolHandler:  registry.Handler(env),
		MaxIters:     e.SpawnDefaults.MaxIters,
		MaxTokensRun: e.SpawnDefaults.MaxTokensRun,
		Sink:         e.Sink,
	})
	return err
}

// renderHook expands phase.PromptHook against rc using text/template. The
// per_finding template returns a non-nil expansion list which the caller
// uses to fan out instead of rendering a single hook.
func renderHook(phase Phase, rc RunContext, findings []findingRecord) (string, []perFindingExpansion, error) {
	if phase.PromptHookTemplate == PromptHookTemplatePerFinding {
		thresh := phase.SeverityThreshold
		if thresh == "" {
			thresh = "medium"
		}
		var expansions []perFindingExpansion
		for _, f := range findings {
			if !severityAtLeast(f.severity, thresh) {
				continue
			}
			expansions = append(expansions, perFindingExpansion{
				findingID: f.id,
				severity:  f.severity,
				file:      f.file,
				line:      f.line,
			})
		}
		return "", expansions, nil
	}
	if strings.TrimSpace(phase.PromptHook) == "" {
		return "", nil, nil
	}
	tmpl, err := template.New("hook").Parse(phase.PromptHook)
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, rc); err != nil {
		return "", nil, err
	}
	return buf.String(), nil, nil
}

func defaultAgentLookup(name string) (*agent.AgentConfig, error) {
	cfg := agent.GetBuiltinAgent(name)
	if cfg == nil {
		return nil, fmt.Errorf("agent %q not found", name)
	}
	return cfg, nil
}

// findingObserver collects newly-created findings from finding_create
// tool calls so per_finding expansion can iterate them.
type findingObserver struct {
	mu      sync.Mutex
	records []findingRecord
}

type findingRecord struct {
	id, severity, file string
	line               int
}

func (o *findingObserver) OnFindingCreated(id, severity, file string, line int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, findingRecord{id: id, severity: severity, file: file, line: line})
}

func (o *findingObserver) snapshot() []findingRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]findingRecord, len(o.records))
	copy(out, o.records)
	return out
}

// severityAtLeast returns true when have >= threshold per the severity
// ordering critical>high>medium>low>info.
func severityAtLeast(have, threshold string) bool {
	rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	return rank[have] >= rank[threshold]
}
