// Package fake provides a scriptable, in-process LLM provider used by
// tests. It replays a pre-recorded sequence of Events per Chat call.
package fake

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/diffsec/quokka/internal/llm"
)

// Provider is a scripted Provider that replays one Event sequence per
// Chat call. Each call advances to the next script in turn.
type Provider struct {
	id      string
	mu      sync.Mutex
	scripts [][]llm.Event
	idx     int
	// Calls records the ChatRequest passed to each Chat call so tests
	// can assert against them.
	calls []llm.ChatRequest
}

// New constructs a Provider with the given id and one script per Chat
// call. The first call replays scripts[0], the second scripts[1], etc.
// Calling Chat more times than scripts is an error.
func New(id string, scripts ...[]llm.Event) *Provider {
	return &Provider{id: id, scripts: scripts}
}

// ID implements llm.Provider.
func (p *Provider) ID() string {
	if p.id == "" {
		return "fake"
	}
	return p.id
}

// Calls returns a copy of the recorded ChatRequest list.
func (p *Provider) Calls() []llm.ChatRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]llm.ChatRequest, len(p.calls))
	copy(out, p.calls)
	return out
}

// Chat implements llm.Provider. Each call replays the next script in
// order. The returned channel is closed after the script drains or the
// context is cancelled.
func (p *Provider) Chat(ctx context.Context, req llm.ChatRequest) (<-chan llm.Event, error) {
	p.mu.Lock()
	if p.idx >= len(p.scripts) {
		p.mu.Unlock()
		return nil, fmt.Errorf("fake provider %s: no script for call %d", p.id, p.idx)
	}
	script := p.scripts[p.idx]
	p.idx++
	p.calls = append(p.calls, req)
	p.mu.Unlock()

	ch := make(chan llm.Event, len(script))
	go func() {
		defer close(ch)
		for _, ev := range script {
			select {
			case <-ctx.Done():
				return
			case ch <- ev:
			}
		}
	}()
	return ch, nil
}

// Close implements llm.Provider.
func (p *Provider) Close() error { return nil }

// MustNew is like New but registers the provider so llm.NewProvider can
// vend it (rarely used; tests prefer instantiation).
func MustNew(id string, scripts ...[]llm.Event) *Provider {
	if id == "" {
		panic(errors.New("fake.MustNew: id required"))
	}
	return New(id, scripts...)
}
