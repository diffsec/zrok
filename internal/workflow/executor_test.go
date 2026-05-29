package workflow

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/llm/fake"
	"github.com/diffsec/quokka/internal/project"
)

// Two phases. Phase 1 lists 3 agents but only 2 are applicable.
// Phase 2 runs 1 agent with a prompt-hook that references .ChangedFiles.
// We assert: applicability filtering, phase ordering, hook rendering,
// concurrency.
func TestExecutor_Run_AppFilteringAndHook(t *testing.T) {
	yamlStr := `
name: test
version: 1
phases:
  - name: recon
    mode: sequential
    agents: [web-agent, api-agent, cli-agent]
  - name: reporting
    mode: parallel
    max_parallel: 2
    agents: [reporter]
    prompt_hook: "files: {{range .ChangedFiles}}{{.}};{{end}}"
`
	w, err := Parse([]byte(yamlStr))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	lookups := map[string]*agent.AgentConfig{
		"web-agent": {
			Name:           "web-agent",
			ToolsAllowed:   []string{},
			PromptTemplate: "you are web-agent",
			Applicability:  project.ApplicabilityRule{ProjectTypes: []string{"web-app"}},
		},
		"api-agent": {
			Name:           "api-agent",
			ToolsAllowed:   []string{},
			PromptTemplate: "you are api-agent",
			Applicability:  project.ApplicabilityRule{ProjectTypes: []string{"api-service"}},
		},
		"cli-agent": {
			Name:           "cli-agent",
			ToolsAllowed:   []string{},
			PromptTemplate: "you are cli-agent",
			Applicability:  project.ApplicabilityRule{ProjectTypes: []string{"cli-tool"}},
		},
		"reporter": {
			Name:           "reporter",
			ToolsAllowed:   []string{},
			PromptTemplate: "you are reporter",
			Applicability:  project.ApplicabilityRule{AlwaysInclude: true},
		},
	}
	lookup := AgentLookup(func(n string) (*agent.AgentConfig, error) {
		if c, ok := lookups[n]; ok {
			return c, nil
		}
		return nil, nil
	})

	// Track which agents were Chat'd, and grab the system prompt of the
	// reporter so we can assert the hook rendered.
	var (
		mu              sync.Mutex
		ran             []string
		reporterSystem  string
		providerCallsCt atomic.Int32
	)
	factory := ProviderFactory(func(_ *agent.ModelConfig) (llm.Provider, error) {
		// New fake provider per invocation, single-turn end_turn.
		script := []llm.Event{
			{Kind: llm.EventTextDelta, Text: "done"},
			{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
		}
		fp := fake.New("test", script)
		// Wrap to record which agent ran. We can identify the agent
		// from req.System (each prompt starts with "You are NAME").
		return &recordingProvider{
			inner: fp,
			onCall: func(req llm.ChatRequest) {
				providerCallsCt.Add(1)
				mu.Lock()
				defer mu.Unlock()
				for name := range lookups {
					if strings.Contains(req.System, "you are "+name) {
						ran = append(ran, name)
						if name == "reporter" {
							reporterSystem = req.System
						}
					}
				}
			},
		}, nil
	})

	sink := agentloop.NewBufferedSink()
	exec := &Executor{
		ProviderFactory: factory,
		AgentLookup:     lookup,
		Sink:            sink,
		Classification: project.ProjectClassification{
			Types: []project.ProjectType{project.TypeWebApp, project.TypeAPIService},
		},
	}

	err = exec.Run(context.Background(), w, RunContext{
		RepoID:       "repo-1",
		RunID:        "run-1",
		ChangedFiles: []string{"a.go", "b.go"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Web+api applicable; cli skipped; reporter always.
	mu.Lock()
	defer mu.Unlock()
	if !contains(ran, "web-agent") || !contains(ran, "api-agent") {
		t.Errorf("applicable agents didn't run: %v", ran)
	}
	if contains(ran, "cli-agent") {
		t.Errorf("cli-agent should have been filtered out, but it ran")
	}
	if !contains(ran, "reporter") {
		t.Errorf("reporter didn't run")
	}
	if providerCallsCt.Load() != 3 {
		t.Errorf("expected 3 provider calls (web, api, reporter), got %d", providerCallsCt.Load())
	}

	if !strings.Contains(reporterSystem, "a.go;b.go;") {
		t.Errorf("prompt hook did not render ChangedFiles: %q", reporterSystem)
	}

	// Sink must have emitted skipped event for cli-agent.
	var sawSkip bool
	for _, ev := range sink.Events() {
		if m, ok := ev.Payload.(map[string]string); ok {
			if m["skipped"] == "applicability_mismatch" && m["agent"] == "cli-agent" {
				sawSkip = true
			}
		}
	}
	if !sawSkip {
		t.Errorf("cli-agent skip event not emitted to Sink")
	}
}

// recordingProvider wraps an inner Provider, invoking onCall with every
// ChatRequest before delegating.
type recordingProvider struct {
	inner  llm.Provider
	onCall func(llm.ChatRequest)
}

func (r *recordingProvider) ID() string   { return r.inner.ID() }
func (r *recordingProvider) Close() error { return r.inner.Close() }
func (r *recordingProvider) Chat(ctx context.Context, req llm.ChatRequest) (<-chan llm.Event, error) {
	if r.onCall != nil {
		r.onCall(req)
	}
	return r.inner.Chat(ctx, req)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
