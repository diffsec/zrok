package openai

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/diffsec/quokka/internal/llm"
)

func TestParseSSE_TextThenTool(t *testing.T) {
	raw, err := os.ReadFile("../testdata/openai_text_then_tool.sse")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan llm.Event, 32)
	ParseSSE(bytes.NewReader(raw), ch)
	close(ch)

	var got []llm.Event
	for ev := range ch {
		got = append(got, ev)
	}

	want := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "Hello"},
		{Kind: llm.EventTextDelta, Text: " world"},
		{Kind: llm.EventToolCallStart, ToolUseID: "toolu_01", ToolName: "navigate_read"},
		{Kind: llm.EventToolCallDelta, ToolUseID: "toolu_01", ToolName: "navigate_read", InputDelta: `{"path":`},
		{Kind: llm.EventToolCallDelta, ToolUseID: "toolu_01", ToolName: "navigate_read", InputDelta: `"foo.go"}`},
		{Kind: llm.EventToolCallEnd, ToolUseID: "toolu_01", ToolName: "navigate_read"},
		{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
		{Kind: llm.EventUsageDelta, Usage: llm.Usage{InputTokens: 42, OutputTokens: 17}},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event sequence mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestBuildRequest_RoundTripsToolBlocks(t *testing.T) {
	cfg := llm.DefaultConfigs["openai-compat"].Clone()
	cfg.BaseURL = "http://localhost:11434"
	req := llm.ChatRequest{
		System: "you are a helper",
		Messages: []llm.Message{
			{Role: llm.RoleUser, Content: []llm.ContentBlock{{Type: llm.BlockText, Text: "hi"}}},
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockToolUse, ToolUseID: "t1", ToolName: "navigate_read", ToolInput: []byte(`{"path":"x.go"}`)},
			}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{
				{Type: llm.BlockToolResult, ToolUseID: "t1", ToolResult: "ok"},
			}},
		},
		Tools: []llm.ToolSpec{{Name: "navigate_read", Description: "read", InputSchema: []byte(`{"type":"object"}`)}},
	}
	b, err := buildRequest(cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"role":"system"`)) {
		t.Errorf("system not prepended as message: %s", b)
	}
	if !bytes.Contains(b, []byte(`"role":"tool"`)) {
		t.Errorf("tool_result not rendered as role:tool message: %s", b)
	}
	if !bytes.Contains(b, []byte(`"tool_call_id":"t1"`)) {
		t.Errorf("tool_call_id not set: %s", b)
	}
}
