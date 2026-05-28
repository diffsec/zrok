package agent

import (
	"testing"

	"github.com/diffsec/quokka/internal/llm"
	"gopkg.in/yaml.v3"
)

func TestModelConfig_YAMLRoundTrip(t *testing.T) {
	in := AgentConfig{
		Name:           "test-agent",
		Description:    "x",
		Phase:          PhaseAnalysis,
		ToolsAllowed:   []string{"navigate_read"},
		PromptTemplate: "you are {{.AgentName}}",
		ModelConfig: &ModelConfig{
			ProviderID:    "anthropic",
			Model:         "claude-opus-4-7",
			Temperature:   0.2,
			MaxTokens:     4000,
			NetworkEgress: "default",
		},
	}
	data, err := yaml.Marshal(&in)
	if err != nil {
		t.Fatal(err)
	}
	var out AgentConfig
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.ModelConfig == nil {
		t.Fatal("ModelConfig lost in round-trip")
	}
	if out.ModelConfig.ProviderID != "anthropic" {
		t.Errorf("ProviderID = %q, want anthropic", out.ModelConfig.ProviderID)
	}
	if out.ModelConfig.Model != "claude-opus-4-7" {
		t.Errorf("Model = %q, want claude-opus-4-7", out.ModelConfig.Model)
	}
	if out.ModelConfig.MaxTokens != 4000 {
		t.Errorf("MaxTokens = %d, want 4000", out.ModelConfig.MaxTokens)
	}
}

func TestLoadStrict_RejectsUnknownFields(t *testing.T) {
	data := []byte(`
name: x
description: y
tools_allowed: []
prompt_template: hi
bogus: oops
`)
	_, err := LoadStrict(data)
	if err == nil {
		t.Fatal("expected strict mode to reject unknown field")
	}
}

func TestLoadStrict_AcceptsModelConfig(t *testing.T) {
	data := []byte(`
name: x
description: y
tools_allowed: []
prompt_template: hi
model_config:
  provider_id: anthropic
  model: claude-opus-4-7
  temperature: 0.1
  max_tokens: 1024
`)
	cfg, err := LoadStrict(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ModelConfig == nil || cfg.ModelConfig.Model != "claude-opus-4-7" {
		t.Errorf("unexpected ModelConfig: %#v", cfg.ModelConfig)
	}
}

type fakeResolver struct{}

func (fakeResolver) Allowed(names []string) []llm.ToolSpec {
	out := make([]llm.ToolSpec, 0, len(names))
	for _, n := range names {
		out = append(out, llm.ToolSpec{Name: n, Description: "fake " + n})
	}
	return out
}

func TestGenerateWithToolSpecs_InjectsHookAndTools(t *testing.T) {
	cfg := &AgentConfig{
		Name:           "security-agent",
		ToolsAllowed:   []string{"navigate_read", "memory_write"},
		PromptTemplate: "You are {{.AgentName}}.",
	}
	g := NewPromptGenerator(nil, nil)
	system, _, tools, err := g.GenerateWithToolSpecs(cfg, "Focus on file foo.go.", []string{"foo.go", "bar.go"}, fakeResolver{})
	if err != nil {
		t.Fatalf("GenerateWithToolSpecs: %v", err)
	}
	if !substr(system, "Focus on file foo.go.") {
		t.Errorf("workflow hook not in system prompt:\n%s", system)
	}
	if !substr(system, "foo.go") || !substr(system, "bar.go") {
		t.Errorf("changed files not in system prompt:\n%s", system)
	}
	if len(tools) != 2 {
		t.Errorf("got %d tools, want 2", len(tools))
	}
}

func substr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
