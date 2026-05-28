package llm

import (
	"math"
	"testing"
)

func TestCost_KnownModel(t *testing.T) {
	u := Usage{InputTokens: 1_000_000, OutputTokens: 500_000}
	got := Cost("anthropic", "claude-sonnet-4-5", u)
	want := 3.00 + 0.5*15.00 // 10.50
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("Cost = %v, want %v", got, want)
	}
}

func TestCost_WithCacheTokens(t *testing.T) {
	u := Usage{
		InputTokens:         100_000,
		OutputTokens:        50_000,
		CacheReadTokens:     200_000,
		CacheCreationTokens: 10_000,
	}
	got := Cost("anthropic", "claude-opus-4-7", u)
	want := 0.1*15.00 + 0.05*75.00 + 0.2*1.50 + 0.01*18.75
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("Cost = %v, want %v", got, want)
	}
}

func TestCost_UnknownProvider(t *testing.T) {
	got := Cost("nope", "no-such-model", Usage{InputTokens: 1_000_000})
	if got != 0 {
		t.Fatalf("Cost for unknown provider = %v, want 0", got)
	}
}

func TestCost_UnknownModel(t *testing.T) {
	got := Cost("anthropic", "claude-experimental-99", Usage{InputTokens: 1_000_000})
	if got != 0 {
		t.Fatalf("Cost for unknown model = %v, want 0", got)
	}
}

func TestCost_OpenAICompat(t *testing.T) {
	u := Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000}
	got := Cost("openai-compat", "gpt-4o-mini", u)
	want := 0.15 + 0.60
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("Cost = %v, want %v", got, want)
	}
}
