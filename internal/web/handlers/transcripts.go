// Package handlers — transcript drawer.
//
// GET /repos/{repo_id}/runs/{run_id}/agents/{slot}/transcript renders the
// per-agent NDJSON transcript file as a slide-in drawer. For live runs the
// drawer mounts an inner SSE listener filtered by `slot`.
package handlers

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
)

// TranscriptDrawerHandler renders the per-agent transcript partial.
type TranscriptDrawerHandler struct {
	Stores *store.Stores
}

// Serve handles the drawer partial GET.
func (h *TranscriptDrawerHandler) Serve(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	runID := r.PathValue("run_id")
	slot := r.PathValue("slot")
	if repoID == "" || runID == "" || slot == "" {
		http.Error(w, "missing path values", http.StatusBadRequest)
		return
	}

	// Look up the run to confirm repo association and grab status.
	run, err := h.Stores.Runs.Get(r.Context(), runID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run.RepoID != repoID {
		http.NotFound(w, r)
		return
	}

	// Load the transcript metadata. There may be no row yet for a still-
	// streaming agent; we render the empty shell and rely on the inner SSE
	// listener for live tail.
	var lines []templates.TranscriptLine
	transcripts, _ := h.Stores.Transcripts.List(r.Context(), runID)
	for _, t := range transcripts {
		if t.AgentName != slot {
			continue
		}
		ls, err := readTranscriptFile(t.StorageURI)
		if err == nil {
			lines = append(lines, ls...)
		}
		break
	}

	v := templates.TranscriptDrawerView{
		RepoID:    repoID,
		RunID:     runID,
		AgentName: slot,
		Lines:     lines,
		Live:      !isTerminal(run.Status),
	}
	renderHTML(w, r, templates.TranscriptDrawer(v))
}

// readTranscriptFile parses an NDJSON file URI of the form file:///path.
// Returns an empty slice when the file is absent or partial.
func readTranscriptFile(uri string) ([]templates.TranscriptLine, error) {
	path := strings.TrimPrefix(uri, "file://")
	// Tolerate file:/// (3 slashes) by re-removing the leading slash duplicate.
	if u, err := url.Parse(uri); err == nil && u.Scheme == "file" && u.Path != "" {
		path = u.Path
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []templates.TranscriptLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var ev struct {
			RunID     string          `json:"run_id"`
			AgentName string          `json:"agent_name"`
			Seq       int             `json:"seq"`
			TS        string          `json:"ts"`
			Kind      string          `json:"kind"`
			Payload   json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		out = append(out, templates.TranscriptLine{
			Seq:     ev.Seq,
			TS:      ev.TS,
			Kind:    ev.Kind,
			Payload: string(ev.Payload),
		})
	}
	return out, nil
}
