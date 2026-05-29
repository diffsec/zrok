package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/llm/fake"
)

// A parent loop emits a spawn_agent tool call; the spawn_agent tool runs
// a child loop with its own fake provider; the child's summary flows back
// to the parent as a tool_result content block.
func TestSpawnAgent_ParentChildRoundTrip(t *testing.T) {
	// Child agent definition for the lookup.
	childAgent := &agent.AgentConfig{
		Name:         "scout",
		Description:  "child scout agent",
		ToolsAllowed: []string{}, // no tools — replies with text only
	}

	// Child's fake provider: one turn, text + end_turn.
	childScript := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "scout report: clean"},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	childProvider := fake.New("child", childScript)

	// Parent's fake provider: turn 1 issues a spawn_agent tool call;
	// turn 2 acknowledges and ends.
	parentScript1 := []llm.Event{
		{Kind: llm.EventToolCallStart, ToolUseID: "t1", ToolName: "spawn_agent"},
		{Kind: llm.EventToolCallDelta, ToolUseID: "t1", ToolName: "spawn_agent", InputDelta: `{"agent_name":"scout","prompt_fragment":"check repo"}`},
		{Kind: llm.EventToolCallEnd, ToolUseID: "t1", ToolName: "spawn_agent"},
		{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
	}
	parentScript2 := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "got it"},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	parentProvider := fake.New("parent", parentScript1, parentScript2)

	registry := NewRegistry()
	registry.Register(&SpawnAgent{})

	env := &Env{
		AgentName: "orchestrator",
		AgentLookup: func(name string) (*agent.AgentConfig, error) {
			if name == "scout" {
				return childAgent, nil
			}
			return nil, nil
		},
		ProviderFactory: func(_ *agent.ModelConfig) (llm.Provider, error) {
			return childProvider, nil
		},
		SpawnDefaults: SpawnDefaults{MaxIters: 4},
	}

	sink := agentloop.NewBufferedSink()
	res, err := agentloop.Run(context.Background(), agentloop.Spec{
		AgentName:   "orchestrator",
		Provider:    parentProvider,
		InitialUser: "review the repo",
		Tools:       registry.Allowed([]string{"spawn_agent"}),
		ToolHandler: registry.Handler(env),
		Sink:        sink,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.IterCount != 2 {
		t.Fatalf("IterCount = %d, want 2", res.IterCount)
	}

	// The parent's message log should include a tool_result block
	// whose payload contains the child's text.
	var sawToolResult bool
	for _, m := range res.Messages {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult && b.ToolUseID == "t1" {
				if !strings.Contains(b.ToolResult, "scout report: clean") {
					t.Errorf("tool_result content = %q, want it to include child text", b.ToolResult)
				}
				sawToolResult = true
			}
		}
	}
	if !sawToolResult {
		t.Errorf("no tool_result block for spawn_agent call found")
	}
}
