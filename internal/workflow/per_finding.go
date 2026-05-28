package workflow

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/agentloop/tools"
	"github.com/diffsec/quokka/internal/llm"
)

// perFindingExpansion is one fan-out target for a phase with
// prompt_hook_template: per_finding.
type perFindingExpansion struct {
	findingID string
	severity  string
	file      string
	line      int
}

// runPerFinding fans out one child invocation per (agent × eligible
// finding). Used by the reporting phase to drive per-finding review
// agents in PR-4; PR-2's executor wires the loop minimally so a future
// real run does the right thing.
func (e *Executor) runPerFinding(
	ctx context.Context,
	phase Phase,
	expansions []perFindingExpansion,
	lookup AgentLookup,
	registry *tools.Registry,
	rc RunContext,
	obs *findingObserver,
) error {
	for _, name := range phase.Agents {
		cfg, err := lookup(name)
		if err != nil || cfg == nil {
			continue
		}
		for _, fe := range expansions {
			hook := fmt.Sprintf("Reviewing finding %s (%s) at %s:%d.", fe.findingID, fe.severity, fe.file, fe.line)
			if err := e.runFanoutAgent(ctx, cfg, lookup, registry, hook, rc, obs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Executor) runFanoutAgent(
	ctx context.Context,
	cfg *agent.AgentConfig,
	lookup AgentLookup,
	registry *tools.Registry,
	hook string,
	rc RunContext,
	obs *findingObserver,
) error {
	provider, err := e.ProviderFactory(cfg.ModelConfig)
	if err != nil {
		return err
	}
	gen := agent.NewPromptGenerator(e.Project, nil)
	system, _, toolSpecs, err := gen.GenerateWithToolSpecs(cfg, hook, rc.ChangedFiles, registry)
	if err != nil {
		return err
	}
	env := &tools.Env{
		Project:         e.Project,
		Stores:          e.Stores,
		AgentName:       cfg.Name,
		RepoID:          rc.RepoID,
		RunID:           rc.RunID,
		AgentLookup:     func(n string) (*agent.AgentConfig, error) { return lookup(n) },
		ProviderFactory: func(mc *agent.ModelConfig) (llm.Provider, error) { return e.ProviderFactory(mc) },
		SpawnDefaults:   e.SpawnDefaults,
		FindingSink:     obs,
	}
	_, err = agentloop.Run(ctx, agentloop.Spec{
		RunID:        rc.RunID,
		AgentName:    cfg.Name,
		Provider:     provider,
		SystemPrompt: system,
		Tools:        toolSpecs,
		ToolHandler:  registry.Handler(env),
		Sink:         e.Sink,
	})
	return err
}
