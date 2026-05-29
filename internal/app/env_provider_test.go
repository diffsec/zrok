package app_test

import (
	"testing"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/app"
	"github.com/diffsec/quokka/internal/worker/jobs"
)

// TestEnvProviderFactoryReadsLabel asserts that NewEnvProviderFactory
// resolves the right env vars from the spec's default label.
func TestEnvProviderFactoryReadsLabel(t *testing.T) {
	t.Setenv("QUOKKA_PROVIDER_MYORG_KEY", "secret-1")
	t.Setenv("QUOKKA_PROVIDER_MYORG_BASE_URL", "https://api.example.com")
	t.Setenv("QUOKKA_PROVIDER_MYORG_PROTOCOL", "anthropic")
	spec := &jobs.JobSpec{DefaultProviderLabel: "myorg"}
	f := app.NewEnvProviderFactory(spec)
	p, err := f(nil)
	if err != nil {
		t.Fatalf("factory(nil): %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil provider")
	}
}

// TestEnvProviderFactoryPerAgentOverride asserts that the per-agent
// ProviderID overrides the spec's default label.
func TestEnvProviderFactoryPerAgentOverride(t *testing.T) {
	t.Setenv("QUOKKA_PROVIDER_DEFAULT_KEY", "")
	t.Setenv("QUOKKA_PROVIDER_FALLBACK_KEY", "secret-fb")
	t.Setenv("QUOKKA_PROVIDER_FALLBACK_PROTOCOL", "anthropic")
	spec := &jobs.JobSpec{DefaultProviderLabel: "default"}
	mc := &agent.ModelConfig{ProviderID: "fallback"}
	p, err := app.NewEnvProviderFactory(spec)(mc)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if p == nil {
		t.Fatalf("expected non-nil provider")
	}
}

// TestEnvProviderFactoryNoKeyErrors asserts that a missing key surfaces
// a clear error.
func TestEnvProviderFactoryNoKeyErrors(t *testing.T) {
	// Clear any leakage from other tests.
	t.Setenv("QUOKKA_PROVIDER_ABSENT_KEY", "")
	spec := &jobs.JobSpec{DefaultProviderLabel: "absent"}
	_, err := app.NewEnvProviderFactory(spec)(nil)
	if err == nil {
		t.Fatalf("expected error for missing env key, got nil")
	}
}
