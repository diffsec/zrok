// Package transcript wires the agentloop transcript stream to durable storage
// and an in-memory pub/sub for live SSE consumers. The DBSink writes each run's
// transcript file via the TranscriptStore (filesystem-backed) and appends
// timeline_events rows for structured event kinds. The Broadcaster fans events
// out to per-run subscriber channels.
package transcript

import (
	"sync"

	"github.com/diffsec/quokka/internal/agentloop"
)

// Broadcaster is a per-process pub/sub keyed by run_id. Subscribers receive
// every event for that run on a buffered channel; back-pressure causes drops
// rather than blocking the publisher.
type Broadcaster struct {
	mu          sync.Mutex
	subscribers map[string][]chan agentloop.TranscriptEvent
}

// NewBroadcaster constructs an empty in-memory Broadcaster.
func NewBroadcaster() *Broadcaster {
	return &Broadcaster{subscribers: map[string][]chan agentloop.TranscriptEvent{}}
}

// Subscribe registers a subscriber on runID and returns the channel + an
// Unsubscribe func. Buffer size is per-subscriber; choose larger values for
// browsers on flaky links. A typical SSE consumer is fine with 64.
func (b *Broadcaster) Subscribe(runID string, buffer int) (<-chan agentloop.TranscriptEvent, func()) {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan agentloop.TranscriptEvent, buffer)
	b.mu.Lock()
	b.subscribers[runID] = append(b.subscribers[runID], ch)
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.subscribers[runID]
		for i, s := range subs {
			if s == ch {
				b.subscribers[runID] = append(subs[:i], subs[i+1:]...)
				close(ch)
				if len(b.subscribers[runID]) == 0 {
					delete(b.subscribers, runID)
				}
				return
			}
		}
	}
}

// Publish hands ev to every current subscriber on ev.RunID. Drops the event
// for any subscriber whose buffer is full; the publisher never blocks.
func (b *Broadcaster) Publish(ev agentloop.TranscriptEvent) {
	b.mu.Lock()
	subs := append([]chan agentloop.TranscriptEvent(nil), b.subscribers[ev.RunID]...)
	b.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
			// dropped under back-pressure
		}
	}
}

// Close terminates every subscriber on runID and removes the entry.
func (b *Broadcaster) Close(runID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subscribers[runID] {
		close(ch)
	}
	delete(b.subscribers, runID)
}

// Emit implements agentloop.EventSink. It is a thin alias for Publish.
func (b *Broadcaster) Emit(ev agentloop.TranscriptEvent) { b.Publish(ev) }
