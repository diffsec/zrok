// Package llm defines the provider interface, unified content model, and
// streaming event types the agent loop talks to. Adapters live under
// llm/anthropic and llm/openai; the in-process scriptable fake lives under
// llm/fake.
package llm

// Role names for a Message.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Content block types. The same names are used in both directions: the
// provider returns text/tool_use blocks, the caller passes back text and
// tool_result blocks on the next turn.
const (
	BlockText       = "text"
	BlockToolUse    = "tool_use"
	BlockToolResult = "tool_result"
)

// Message is a single turn in a conversation. A message may contain
// multiple ContentBlocks (e.g. an assistant turn that produces text plus
// one or more tool_use blocks).
type Message struct {
	Role    string
	Content []ContentBlock
}

// ContentBlock is the unified content type. Which fields are populated
// depends on Type:
//   - BlockText: Text
//   - BlockToolUse: ToolUseID, ToolName, ToolInput
//   - BlockToolResult: ToolUseID, ToolResult, IsError
type ContentBlock struct {
	Type       string
	Text       string
	ToolUseID  string
	ToolName   string
	ToolInput  []byte
	ToolResult string
	IsError    bool
}

// ToolSpec is what a Provider exposes to the model so it can call into our
// tool registry. InputSchema is a JSON Schema document describing the
// tool's input.
type ToolSpec struct {
	Name        string
	Description string
	InputSchema []byte
}

// ChatRequest is the input to Provider.Chat. System is hoisted into the
// adapter-specific top-level "system" field for Anthropic, or prepended as
// a role:"system" message for OpenAI-compatible.
type ChatRequest struct {
	Model       string
	System      string
	Messages    []Message
	Tools       []ToolSpec
	Temperature float32
	MaxTokens   int
	// StopSequences is currently unused but reserved for future use.
	StopSequences []string
}

// EventKind enumerates the streaming Event types.
type EventKind string

const (
	EventTextDelta     EventKind = "text_delta"
	EventToolCallStart EventKind = "tool_call_start"
	EventToolCallDelta EventKind = "tool_call_delta"
	EventToolCallEnd   EventKind = "tool_call_end"
	EventUsageDelta    EventKind = "usage_delta"
	EventStopReason    EventKind = "stop_reason"
	EventError         EventKind = "error"
)

// StopReason values. Adapters normalize provider-specific stop reasons to
// these.
const (
	StopEndTurn   = "end_turn"
	StopToolUse   = "tool_use"
	StopMaxTokens = "max_tokens"
	StopStop      = "stop"
)

// Event is one item in the streaming Event channel returned by Chat.
//
// For EventTextDelta, Text carries the chunk.
// For EventToolCallStart, ToolUseID + ToolName are set.
// For EventToolCallDelta, ToolUseID + InputDelta are set.
// For EventToolCallEnd, ToolUseID is set.
// For EventUsageDelta, Usage carries the partial token counts.
// For EventStopReason, StopReason is set.
// For EventError, Err is set.
type Event struct {
	Kind       EventKind
	Text       string
	ToolUseID  string
	ToolName   string
	InputDelta string
	Usage      Usage
	StopReason string
	Err        error
}

// Usage is the per-call token accounting. Cache fields are zero for
// providers that don't report them.
type Usage struct {
	InputTokens         int
	OutputTokens        int
	CacheReadTokens     int
	CacheCreationTokens int
}

// Add returns the per-field sum of u and other.
func (u Usage) Add(other Usage) Usage {
	return Usage{
		InputTokens:         u.InputTokens + other.InputTokens,
		OutputTokens:        u.OutputTokens + other.OutputTokens,
		CacheReadTokens:     u.CacheReadTokens + other.CacheReadTokens,
		CacheCreationTokens: u.CacheCreationTokens + other.CacheCreationTokens,
	}
}
