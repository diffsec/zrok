package workflow

import (
	"bytes"
	"fmt"
	"log"

	"gopkg.in/yaml.v3"
)

// Parse decodes a Workflow from YAML bytes. Strict mode: unknown fields
// error.
func Parse(data []byte) (*Workflow, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var w Workflow
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("workflow: parse: %w", err)
	}
	if err := Validate(&w); err != nil {
		return nil, err
	}
	return &w, nil
}

// Validate enforces structural invariants on a parsed Workflow. The
// "reporting phase exists" check is a warning, not an error, because
// some workflows legitimately end on validation.
func Validate(w *Workflow) error {
	if w == nil {
		return fmt.Errorf("workflow: nil")
	}
	if len(w.Phases) == 0 {
		return fmt.Errorf("workflow: at least one phase is required")
	}
	if w.Phases[0].Mode != ModeSequential && w.Phases[0].Mode != "" {
		return fmt.Errorf("workflow: first phase must be sequential (got %q)", w.Phases[0].Mode)
	}
	// Normalize empty mode to sequential.
	for i := range w.Phases {
		if w.Phases[i].Mode == "" {
			w.Phases[i].Mode = ModeSequential
		}
		if w.Phases[i].Mode != ModeSequential && w.Phases[i].Mode != ModeParallel {
			return fmt.Errorf("workflow: phase %q has invalid mode %q", w.Phases[i].Name, w.Phases[i].Mode)
		}
		if w.Phases[i].Name == "" {
			return fmt.Errorf("workflow: phase index %d has no name", i)
		}
	}
	// Warn (don't error) when no reporting phase exists.
	last := w.Phases[len(w.Phases)-1]
	if last.Name != "reporting" {
		log.Printf("workflow: warning: last phase is %q (expected %q)", last.Name, "reporting")
	}
	return nil
}
