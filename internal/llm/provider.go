package llm

import (
	"context"
	"fmt"
	"sync"
)

// Provider is the streaming chat interface every adapter implements.
type Provider interface {
	ID() string
	Chat(ctx context.Context, req ChatRequest) (<-chan Event, error)
	Close() error
}

// adapterRegistry holds Provider constructors keyed by provider id. The
// concrete adapter packages call Register in their init().
var (
	adapterMu sync.RWMutex
	adapters  = map[string]func(*Config) (Provider, error){}
)

// Register installs a constructor for a provider id. Adapter packages call
// this from their init().
func Register(providerID string, build func(*Config) (Provider, error)) {
	adapterMu.Lock()
	defer adapterMu.Unlock()
	adapters[providerID] = build
}

// NewProvider returns a Provider for cfg.ProviderID. Adapter packages must
// be blank-imported by the caller so their init() runs.
func NewProvider(cfg *Config) (Provider, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	adapterMu.RLock()
	build := adapters[cfg.ProviderID]
	adapterMu.RUnlock()
	if build == nil {
		return nil, fmt.Errorf("llm: no adapter registered for provider_id=%s (import the adapter package)", cfg.ProviderID)
	}
	return build(cfg)
}

// RegisteredProviders returns the list of provider ids that have an
// adapter registered.
func RegisteredProviders() []string {
	adapterMu.RLock()
	defer adapterMu.RUnlock()
	out := make([]string, 0, len(adapters))
	for k := range adapters {
		out = append(out, k)
	}
	return out
}
