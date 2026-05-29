package agentloop

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/llm/fake"
)

// Test the canonical 3-turn flow: assistant calls a tool, handler returns
// a result, loop calls assistant again, assistant emits text + stop.
func TestRun_ToolCallThenText(t *testing.T) {
	script1 := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "Looking up..."},
		{Kind: llm.EventToolCallStart, ToolUseID: "t1", ToolName: "navigate_read"},
		{Kind: llm.EventToolCallDelta, ToolUseID: "t1", ToolName: "navigate_read", InputDelta: `{"path":"foo.go"}`},
		{Kind: llm.EventToolCallEnd, ToolUseID: "t1", ToolName: "navigate_read"},
		{Kind: llm.EventUsageDelta, Usage: llm.Usage{InputTokens: 100, OutputTokens: 20}},
		{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
	}
	script2 := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "Done."},
		{Kind: llm.EventUsageDelta, Usage: llm.Usage{InputTokens: 130, OutputTokens: 5}},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	fp := fake.New("test", script1, script2)
	sink := NewBufferedSink()

	var seen []string
	handler := ToolHandlerFunc(func(ctx context.Context, name string, input []byte) (string, bool, error) {
		seen = append(seen, name+"|"+string(input))
		return "file contents: package foo", false, nil
	})

	res, err := Run(context.Background(), Spec{
		RunID:       "run-1",
		AgentName:   "test-agent",
		Provider:    fp,
		InitialUser: "review foo.go",
		ToolHandler: handler,
		Tools:       []llm.ToolSpec{{Name: "navigate_read", Description: "read"}},
		Sink:        sink,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.IterCount != 2 {
		t.Fatalf("IterCount = %d, want 2", res.IterCount)
	}
	if res.StopReason != llm.StopEndTurn {
		t.Fatalf("StopReason = %s, want %s", res.StopReason, llm.StopEndTurn)
	}
	total := res.Usage.InputTokens + res.Usage.OutputTokens
	if total != 255 {
		t.Fatalf("total tokens = %d, want 255", total)
	}
	if len(seen) != 1 || !strings.Contains(seen[0], "navigate_read") || !strings.Contains(seen[0], "foo.go") {
		t.Fatalf("tool calls = %v, want one navigate_read on foo.go", seen)
	}

	kinds := sink.Kinds()
	wantKinds := []EventKind{
		KindAgentStart, KindUserMsg,
		KindAssistantText, KindToolCall, KindUsage,
		KindToolResult,
		KindAssistantText, KindUsage,
	}
	if len(kinds) != len(wantKinds) {
		t.Fatalf("transcript event kinds = %v, want %v", kinds, wantKinds)
	}
	for i, k := range wantKinds {
		if kinds[i] != k {
			t.Fatalf("transcript kind[%d] = %s, want %s (full: %v)", i, kinds[i], k, kinds)
		}
	}
}

func TestRun_MaxItersHit(t *testing.T) {
	// Build 5 scripts that each return a tool_use; loop with MaxIters=3
	// should abort.
	scripts := make([][]llm.Event, 5)
	for i := range scripts {
		scripts[i] = []llm.Event{
			{Kind: llm.EventToolCallStart, ToolUseID: "t", ToolName: "navigate_list"},
			{Kind: llm.EventToolCallDelta, ToolUseID: "t", ToolName: "navigate_list", InputDelta: `{}`},
			{Kind: llm.EventToolCallEnd, ToolUseID: "t", ToolName: "navigate_list"},
			{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
		}
	}
	fp := fake.New("test", scripts...)
	sink := NewBufferedSink()

	res, err := Run(context.Background(), Spec{
		Provider:    fp,
		MaxIters:    3,
		InitialUser: "go",
		ToolHandler: ToolHandlerFunc(func(_ context.Context, _ string, _ []byte) (string, bool, error) {
			return "ok", false, nil
		}),
		Sink: sink,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.IterCount != 3 {
		t.Fatalf("IterCount = %d, want 3", res.IterCount)
	}
	// Last sink event should be loop_aborted_max_iters.
	evs := sink.Events()
	if evs[len(evs)-1].Kind != KindLoopAbortedMaxIters {
		t.Fatalf("last event = %s, want %s", evs[len(evs)-1].Kind, KindLoopAbortedMaxIters)
	}
}

func TestRun_BudgetExceeded(t *testing.T) {
	script := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "spending..."},
		{Kind: llm.EventUsageDelta, Usage: llm.Usage{InputTokens: 5000, OutputTokens: 5000}},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	fp := fake.New("test", script)
	sink := NewBufferedSink()
	res, err := Run(context.Background(), Spec{
		Provider:     fp,
		ToolHandler:  ToolHandlerFunc(noop),
		MaxTokensRun: 1000,
		Sink:         sink,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Usage.InputTokens+res.Usage.OutputTokens <= 1000 {
		t.Fatalf("expected usage to exceed cap")
	}
	// Should see a budget_exceeded event.
	found := false
	for _, e := range sink.Events() {
		if e.Kind == KindBudgetExceeded {
			found = true
		}
	}
	if !found {
		t.Fatalf("budget_exceeded event not emitted")
	}
}

func TestRun_ContextCancel(t *testing.T) {
	// A long script that the loop should never finish if the context is
	// cancelled before Chat returns.
	script := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "..."},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	fp := fake.New("test", script)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := Run(ctx, Spec{
		Provider:    fp,
		ToolHandler: ToolHandlerFunc(noop),
	})
	if err == nil {
		t.Fatalf("expected context cancellation error")
	}
}

func TestRun_ToolHandlerError(t *testing.T) {
	script1 := []llm.Event{
		{Kind: llm.EventToolCallStart, ToolUseID: "t1", ToolName: "boom"},
		{Kind: llm.EventToolCallDelta, ToolUseID: "t1", ToolName: "boom", InputDelta: "{}"},
		{Kind: llm.EventToolCallEnd, ToolUseID: "t1", ToolName: "boom"},
		{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
	}
	script2 := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "ack"},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	fp := fake.New("test", script1, script2)
	sink := NewBufferedSink()
	_, err := Run(context.Background(), Spec{
		Provider: fp,
		ToolHandler: ToolHandlerFunc(func(_ context.Context, _ string, _ []byte) (string, bool, error) {
			return "tool failed badly", true, nil
		}),
		Sink: sink,
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	// Confirm the tool_result event recorded is_error.
	var sawErr bool
	for _, e := range sink.Events() {
		if e.Kind == KindToolResult {
			if m, ok := e.Payload.(map[string]any); ok {
				if isErr, _ := m["is_error"].(bool); isErr {
					sawErr = true
				}
			}
		}
	}
	if !sawErr {
		t.Fatalf("expected tool_result with is_error=true")
	}
}

func noop(_ context.Context, _ string, _ []byte) (string, bool, error) {
	return "ok", false, nil
}

// Ensure transcripts are sorted by Seq.
func TestTranscriptOrdering(t *testing.T) {
	sink := NewBufferedSink()
	sink.Emit(TranscriptEvent{Seq: 1, Timestamp: time.Now()})
	sink.Emit(TranscriptEvent{Seq: 2, Timestamp: time.Now()})
	got := sink.Events()
	if got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("ordering wrong: %#v", got)
	}
}
