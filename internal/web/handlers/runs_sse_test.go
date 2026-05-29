package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/store"
)

// fakeBroadcaster lets the SSE test drive synthetic events without spinning
// up the real transcript.Broadcaster.
type fakeBroadcaster struct {
	ch chan agentloop.TranscriptEvent
}

func (f *fakeBroadcaster) Subscribe(runID string, buffer int) (<-chan agentloop.TranscriptEvent, func()) {
	return f.ch, func() {}
}

func TestRunsSSE_TerminalReplaysAndCloses(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	repo, run := seedRepoAndRun(t, stores, "completed")
	// Seed a couple of timeline events.
	_ = stores.Events.Append(ctx, run.ID, "phase_start", `{"state":"running"}`)
	_ = stores.Events.Append(ctx, run.ID, "agent_start", `{"agent":"injection-agent"}`)
	_ = stores.Events.Append(ctx, run.ID, "agent_end", `{"agent":"injection-agent"}`)
	_ = stores.Events.Append(ctx, run.ID, "run_completed", `{"findings":0}`)

	h := &RunsSSEHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{repo_id}/runs/{run_id}/events", h.ServeSSE)

	req := httptest.NewRequest(http.MethodGet, "/repos/"+repo.ID+"/runs/"+run.ID+"/events", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "event: phase_start") {
		t.Errorf("missing phase_start: %s", body)
	}
	if !strings.Contains(body, "event: agent_start") {
		t.Errorf("missing agent_start: %s", body)
	}
	if !strings.Contains(body, "event: end") {
		t.Errorf("expected terminal end event: %s", body)
	}
	if got := w.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("content type = %q", got)
	}
}

func TestRunsSSE_LiveStreamsBroadcastEvents(t *testing.T) {
	stores := newTestStores(t)
	repo, run := seedRepoAndRun(t, stores, "running")

	fb := &fakeBroadcaster{ch: make(chan agentloop.TranscriptEvent, 4)}
	h := &RunsSSEHandler{Stores: stores, Broadcaster: fb, Heartbeat: 50 * time.Millisecond}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{repo_id}/runs/{run_id}/events", h.ServeSSE)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Drive synthetic events from another goroutine after subscribe.
	go func() {
		time.Sleep(60 * time.Millisecond)
		fb.ch <- agentloop.TranscriptEvent{
			RunID: run.ID, AgentName: "injection-agent",
			Seq: 1, Timestamp: time.Now(),
			Kind: agentloop.KindToolCall,
			Payload: map[string]any{"tool": "finding_create"},
		}
		time.Sleep(20 * time.Millisecond)
		// Flip status to terminal and close the channel so the handler exits.
		_ = stores.Runs.MarkCompleted(context.Background(), run.ID, "completed", time.Now())
	}()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/repos/"+repo.ID+"/runs/"+run.ID+"/events", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	var collected strings.Builder
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			collected.Write(buf[:n])
		}
		if strings.Contains(collected.String(), "event: end") {
			break
		}
		if err != nil {
			break
		}
	}

	body := collected.String()
	if !strings.Contains(body, "event: tool_call") {
		t.Errorf("missing tool_call: %s", body)
	}
	if !strings.Contains(body, "injection-agent") {
		t.Errorf("missing agent name: %s", body)
	}
	if !strings.Contains(body, "event: end") {
		t.Errorf("expected end event after terminal: %s", body)
	}
}

func seedRepoAndRun(t *testing.T, stores *store.Stores, status string) (*store.Repository, *store.Run) {
	t.Helper()
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("org: %v", err)
	}
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 4242, FullName: "acme/x", DefaultBranch: "main", State: "ready"}
	if err := stores.Repos.Create(ctx, repo); err != nil {
		t.Fatalf("repo: %v", err)
	}
	run := &store.Run{RepoID: repo.ID, Trigger: "manual", Status: status, HeadSHA: "deadbeef"}
	if err := stores.Runs.Create(ctx, run); err != nil {
		t.Fatalf("run: %v", err)
	}
	return repo, run
}
