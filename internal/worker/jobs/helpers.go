package jobs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
)

// jobSpecForRun builds the container spec for one RunPR/RunManual job.
// The runner image's entrypoint reads /job/spec.json and runs the
// in-process agent loop against /workspace.
func jobSpecForRun(deps *Deps, repoID, runID, repoPath string) container.ContainerSpec {
	spec := map[string]any{
		"run_id":  runID,
		"repo_id": repoID,
	}
	b, _ := json.Marshal(spec)
	statePath := ""
	if deps.DataRoot != "" {
		statePath = deps.DataRoot + "/state/" + repoID
	}
	return container.ContainerSpec{
		Image:       deps.RunnerImage,
		JobSpecJSON: b,
		RepoPath:    repoPath,
		StatePath:   statePath,
		Env: map[string]string{
			"QUOKKA_RUN_ID":  runID,
			"QUOKKA_REPO_ID": repoID,
		},
		Resources: container.DefaultResources(),
	}
}

// parseTranscriptLine extracts a TranscriptEvent from a runner NDJSON line.
// Lines that don't match are returned with the raw line as Payload.
func parseTranscriptLine(runID, line string) agentloop.TranscriptEvent {
	var w struct {
		RunID     string `json:"run_id"`
		AgentName string `json:"agent_name"`
		Seq       int    `json:"seq"`
		Timestamp string `json:"ts"`
		Kind      string `json:"kind"`
		Payload   any    `json:"payload"`
	}
	if err := json.Unmarshal([]byte(line), &w); err != nil {
		return agentloop.TranscriptEvent{RunID: runID, Kind: "raw", Payload: line, Timestamp: time.Now()}
	}
	t, _ := time.Parse(time.RFC3339Nano, w.Timestamp)
	if t.IsZero() {
		t = time.Now()
	}
	rid := w.RunID
	if rid == "" {
		rid = runID
	}
	return agentloop.TranscriptEvent{
		RunID:     rid,
		AgentName: w.AgentName,
		Seq:       w.Seq,
		Timestamp: t,
		Kind:      agentloop.EventKind(w.Kind),
		Payload:   w.Payload,
	}
}

// toGitHubFindings narrows the store.FindingRow set to the subset the
// feedback writers consume.
func toGitHubFindings(fs []*store.FindingRow) []github.Finding {
	out := make([]github.Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, github.Finding{
			Title:       f.Title,
			Severity:    f.Severity,
			CWE:         f.CWE,
			File:        f.File,
			LineStart:   f.LineStart,
			Description: f.Description,
			Remediation: f.Remediation,
		})
	}
	return out
}

// summarizeFindings renders the summary comment body.
func summarizeFindings(fs []*store.FindingRow) string {
	if len(fs) == 0 {
		return "Quokka completed. No new findings."
	}
	by := map[string]int{}
	for _, f := range fs {
		by[strings.ToLower(f.Severity)]++
	}
	var sb strings.Builder
	sb.WriteString("Quokka findings on this PR\n\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if by[sev] > 0 {
			fmt.Fprintf(&sb, "- %s: %d\n", sev, by[sev])
		}
	}
	sb.WriteString("\nSee the run for details.\n")
	return sb.String()
}

// buildInlineComments turns findings into review comments. Position
// resolution is left to the feedback layer when a diff is available; in
// PR-4 we use line as a fallback (PR-5 wires the real diff parse).
func buildInlineComments(fs []*store.FindingRow) []github.ReviewComment {
	out := make([]github.ReviewComment, 0, len(fs))
	for _, f := range fs {
		if f.File == "" || f.LineStart <= 0 {
			continue
		}
		body := fmt.Sprintf("**%s**: %s", strings.ToUpper(f.Severity), f.Title)
		if f.Description != "" {
			body += "\n\n" + f.Description
		}
		out = append(out, github.ReviewComment{
			Path:     f.File,
			Position: f.LineStart, // will be replaced with diff position when caller has a diff
			Body:     body,
		})
	}
	return out
}
