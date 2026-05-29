package agentloop

import (
	"sync"
	"time"
)

// EventKind enumerates the timeline event types emitted from a Run.
type EventKind string

const (
	KindAgentStart          EventKind = "agent_start"
	KindAgentEnd            EventKind = "agent_end"
	KindUserMsg             EventKind = "user_msg"
	KindAssistantText       EventKind = "assistant_text"
	KindToolCall            EventKind = "tool_call"
	KindToolResult          EventKind = "tool_result"
	KindUsage               EventKind = "usage"
	KindError               EventKind = "error"
	KindLoopAbortedMaxIters EventKind = "loop_aborted_max_iters"
	KindBudgetExceeded      EventKind = "budget_exceeded"
)

// TranscriptEvent is one entry on a Run's transcript. Payload is whatever
// the emitter chose to attach; the loop puts strings, maps, or structured
// data here.
type TranscriptEvent struct {
	RunID     string
	AgentName string
	Seq       int
	Timestamp time.Time
	Kind      EventKind
	Payload   any
}

// EventSink consumes transcript events. Implementations should be
// non-blocking and goroutine-safe.
type EventSink interface {
	Emit(TranscriptEvent)
}

// MultiSink fans out one Emit call to N child sinks.
type MultiSink struct {
	sinks []EventSink
}

// NewMultiSink constructs a MultiSink over the given children.
func NewMultiSink(sinks ...EventSink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

// Emit forwards to every child sink in order.
func (m *MultiSink) Emit(ev TranscriptEvent) {
	for _, s := range m.sinks {
		s.Emit(ev)
	}
}

// BufferedSink collects all events into a slice for tests. Goroutine-safe.
type BufferedSink struct {
	mu     sync.Mutex
	events []TranscriptEvent
}

// NewBufferedSink constructs an empty BufferedSink.
func NewBufferedSink() *BufferedSink { return &BufferedSink{} }

// Emit appends ev to the in-memory slice.
func (b *BufferedSink) Emit(ev TranscriptEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, ev)
}

// Events returns a copy of the recorded events.
func (b *BufferedSink) Events() []TranscriptEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]TranscriptEvent, len(b.events))
	copy(out, b.events)
	return out
}

// Kinds returns the EventKind slice for the recorded events in order.
func (b *BufferedSink) Kinds() []EventKind {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]EventKind, len(b.events))
	for i, e := range b.events {
		out[i] = e.Kind
	}
	return out
}
