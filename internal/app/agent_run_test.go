package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentSidecarEmitsNDJSON(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")
	spec := JobSpec{RunID: "run-1", RepoID: "repo-1"}
	b, _ := json.Marshal(spec)
	if err := os.WriteFile(specPath, b, 0o600); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	var buf bytes.Buffer
	if err := runAgentSidecar(specPath, &buf); err != nil {
		t.Fatalf("runAgentSidecar: %v", err)
	}
	out := strings.TrimRight(buf.String(), "\n")
	lines := strings.Split(out, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 NDJSON lines, got %d: %q", len(lines), out)
	}
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d not valid JSON: %v\nline=%s", i, err, line)
		}
		if m["run_id"] != "run-1" {
			t.Errorf("line %d run_id=%v want run-1", i, m["run_id"])
		}
	}
}
