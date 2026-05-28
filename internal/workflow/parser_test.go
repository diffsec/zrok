package workflow

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParse_Minimal(t *testing.T) {
	yamlStr := `
name: default
version: 1
phases:
  - name: recon
    mode: sequential
    agents: [recon-agent]
  - name: reporting
    mode: sequential
    agents: [reporter]
`
	w, err := Parse([]byte(yamlStr))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if w.Name != "default" {
		t.Errorf("Name = %q, want default", w.Name)
	}
	if len(w.Phases) != 2 {
		t.Fatalf("Phases len = %d, want 2", len(w.Phases))
	}
	if w.Phases[0].Mode != ModeSequential {
		t.Errorf("first phase mode = %q, want sequential", w.Phases[0].Mode)
	}
}

func TestParse_StrictRejectsUnknownFields(t *testing.T) {
	yamlStr := `
name: default
version: 1
phases:
  - name: recon
    mode: sequential
    agents: [a]
    bogus_field: oops
`
	_, err := Parse([]byte(yamlStr))
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "bogus_field") {
		t.Errorf("error should mention unknown field, got: %v", err)
	}
}

func TestParse_RejectsParallelFirstPhase(t *testing.T) {
	yamlStr := `
name: bad
phases:
  - name: recon
    mode: parallel
    agents: [a]
`
	_, err := Parse([]byte(yamlStr))
	if err == nil {
		t.Fatal("expected error: first phase must be sequential")
	}
}

func TestParse_PhaseModeNormalisation(t *testing.T) {
	yamlStr := `
name: ok
phases:
  - name: recon
    agents: [a]
  - name: reporting
    mode: parallel
    agents: [b]
`
	w, err := Parse([]byte(yamlStr))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if w.Phases[0].Mode != ModeSequential {
		t.Errorf("empty mode not normalised to sequential: %q", w.Phases[0].Mode)
	}
}

func TestParse_RoundTripYAML(t *testing.T) {
	in := &Workflow{
		Name:    "rt",
		Version: 2,
		Phases: []Phase{
			{Name: "recon", Mode: ModeSequential, Agents: []string{"a"}},
			{Name: "reporting", Mode: ModeParallel, MaxParallel: 4, Agents: []string{"b", "c"}, PromptHook: "{{.RunID}}"},
		},
	}
	data, err := yaml.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out.Name != in.Name || len(out.Phases) != len(in.Phases) {
		t.Fatalf("round trip mismatch: %#v vs %#v", out, in)
	}
	if out.Phases[1].PromptHook != "{{.RunID}}" {
		t.Errorf("PromptHook lost in round-trip")
	}
}
