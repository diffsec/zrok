package llm

import (
	"fmt"
	"time"
)

// Config is the per-provider configuration consumed by NewProvider.
type Config struct {
	// ProviderID identifies the adapter: "anthropic" or "openai-compat".
	ProviderID string
	// BaseURL is the API root. May be empty for adapters with a default.
	BaseURL string
	// APIKeyEnv is the environment variable to read the API key from.
	APIKeyEnv string
	// APIKey is an explicit override; when set, APIKeyEnv is ignored.
	APIKey string
	// DefaultModel is used when ChatRequest.Model is empty.
	DefaultModel string
	// Temperature is the default sampling temperature.
	Temperature float32
	// MaxTokens is the default per-response cap.
	MaxTokens int
	// Timeout is the per-request HTTP timeout.
	Timeout time.Duration
}

// Clone returns a shallow copy.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// DefaultConfigs holds the built-in defaults for each provider id. Adapters
// that need a base URL pre-set (anthropic) provide one; openai-compat
// requires the caller to fill BaseURL because it's used against many
// different upstreams.
var DefaultConfigs = map[string]*Config{
	"anthropic": {
		ProviderID:   "anthropic",
		BaseURL:      "https://api.anthropic.com",
		APIKeyEnv:    "ANTHROPIC_API_KEY",
		DefaultModel: "claude-sonnet-4-5",
		Temperature:  0,
		MaxTokens:    8192,
		Timeout:      120 * time.Second,
	},
	"openai-compat": {
		ProviderID:   "openai-compat",
		BaseURL:      "",
		APIKeyEnv:    "OPENAI_API_KEY",
		DefaultModel: "gpt-4o-mini",
		Temperature:  0,
		MaxTokens:    4096,
		Timeout:      120 * time.Second,
	},
}

// ValidateConfig fills in defaults from DefaultConfigs and validates the
// resulting config.
func ValidateConfig(c *Config) error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.ProviderID == "" {
		return fmt.Errorf("provider_id is required")
	}
	def, ok := DefaultConfigs[c.ProviderID]
	if !ok {
		return fmt.Errorf("unknown provider_id: %s", c.ProviderID)
	}
	if c.BaseURL == "" {
		c.BaseURL = def.BaseURL
	}
	if c.BaseURL == "" {
		return fmt.Errorf("base_url is required for provider %s", c.ProviderID)
	}
	if c.APIKeyEnv == "" {
		c.APIKeyEnv = def.APIKeyEnv
	}
	if c.DefaultModel == "" {
		c.DefaultModel = def.DefaultModel
	}
	if c.MaxTokens == 0 {
		c.MaxTokens = def.MaxTokens
	}
	if c.Timeout == 0 {
		c.Timeout = def.Timeout
	}
	return nil
}
