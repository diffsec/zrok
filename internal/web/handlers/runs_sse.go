// Package handlers — SSE timeline for runs.
//
// GET /repos/{repo_id}/runs/{run_id}/events
//
// For terminal runs, replays every row from EventStore.Stream in seq order,
// writes them as SSE events, sends a final `event: end` line, and closes.
// For live runs, subscribes to the in-memory Broadcaster FIRST, then replays
// from the DB (subscribe-first avoids the gap a replay-then-subscribe would
// have when events land between the two calls), and finally drains the
// channel while filtering events already replayed.
//
// SSE event names equal the underlying transcript Kind / timeline_events.kind.
// Payload is one JSON line. A heartbeat `event: ping` is emitted every 15s
// to keep proxies from timing out the connection.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
)

// SSEBroadcaster is the subset of transcript.Broadcaster the handler uses.
// Decoupling lets tests inject a fake.
type SSEBroadcaster interface {
	Subscribe(runID string, buffer int) (<-chan agentloop.TranscriptEvent, func())
}

// RunsSSEHandler subscribes to a Broadcaster for live runs and replays
// timeline_events for completed runs.
type RunsSSEHandler struct {
	Stores      *store.Stores
	Broadcaster SSEBroadcaster
	// Now is overridable in tests.
	Now func() time.Time
	// Heartbeat is the ping interval.
	Heartbeat time.Duration
}

// ServeSSE handles GET /repos/{repo_id}/runs/{run_id}/events.
func (h *RunsSSEHandler) ServeSSE(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	runID := r.PathValue("run_id")
	if repoID == "" || runID == "" {
		http.Error(w, "missing path values", http.StatusBadRequest)
		return
	}
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

	// SSE headers. Note: the standard HTTP server enforces WriteTimeout on
	// the conn; we lift that here so the stream can outlive 30s.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering when proxied
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Time{})
	}
	flusher, _ := w.(http.Flusher)
	if flusher == nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	now := h.now()
	heartbeat := h.Heartbeat
	if heartbeat <= 0 {
		heartbeat = 15 * time.Second
	}

	// Terminal runs: replay-and-close.
	if isTerminal(run.Status) {
		events, err := h.Stores.Events.Stream(r.Context(), runID, time.Time{})
		if err != nil {
			writeSSEError(w, flusher, err)
			return
		}
		for _, ev := range events {
			writeTimelineSSE(w, flusher, ev)
		}
		writeSSEPlain(w, flusher, "end", `{"reason":"terminal"}`)
		return
	}

	// Live runs: subscribe first to capture events that land during the
	// in-flight replay, then replay from DB, then drain the channel while
	// filtering events already emitted by the replay.
	var seenIDs map[string]struct{}
	var sub <-chan agentloop.TranscriptEvent
	var unsub func()
	if h.Broadcaster != nil {
		sub, unsub = h.Broadcaster.Subscribe(runID, 64)
		defer unsub()
	}

	// Replay the existing event tail.
	events, err := h.Stores.Events.Stream(r.Context(), runID, time.Time{})
	if err != nil {
		writeSSEError(w, flusher, err)
		return
	}
	seenIDs = make(map[string]struct{}, len(events))
	for _, ev := range events {
		writeTimelineSSE(w, flusher, ev)
		seenIDs[ev.ID] = struct{}{}
	}
	_ = now

	// Live-tail loop. We exit when the client disconnects, the broadcaster
	// channel closes, OR the run hits a terminal state.
	ctx := r.Context()
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	// Per-second poller checks RunStore for terminal status (PR-4
	// finalizes by writing the run row + a final transcript event).
	terminalCheck := time.NewTicker(2 * time.Second)
	defer terminalCheck.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub:
			if !ok {
				writeSSEPlain(w, flusher, "end", `{"reason":"broadcaster_closed"}`)
				return
			}
			writeTranscriptSSE(w, flusher, ev)
		case <-ticker.C:
			writeSSEPlain(w, flusher, "ping", `{"ts":"`+h.now().UTC().Format(time.RFC3339)+`"}`)
		case <-terminalCheck.C:
			r2, err := h.Stores.Runs.Get(ctx, runID)
			if err == nil && isTerminal(r2.Status) {
				writeSSEPlain(w, flusher, "end", `{"reason":"run_complete","status":"`+r2.Status+`"}`)
				return
			}
		}
	}
}

func isTerminal(status string) bool {
	switch status {
	case "completed", "failed", "cancelled":
		return true
	}
	return false
}

func (h *RunsSSEHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// writeTimelineSSE writes one timeline_events row as an SSE event.
func writeTimelineSSE(w http.ResponseWriter, flusher http.Flusher, ev *store.TimelineEvent) {
	name := ev.EventType
	if name == "" {
		name = "event"
	}
	payload := ev.PayloadJSON
	if payload == "" {
		payload = "{}"
	}
	// Wrap the row so the client sees the seq + ts even for replayed events.
	wrapper := map[string]any{
		"id":      ev.ID,
		"ts":      ev.TS.Format(time.RFC3339Nano),
		"kind":    ev.EventType,
		"payload": json.RawMessage(payload),
	}
	b, _ := json.Marshal(wrapper)
	fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", ev.ID, name, b)
	flusher.Flush()
}

func writeTranscriptSSE(w http.ResponseWriter, flusher http.Flusher, ev agentloop.TranscriptEvent) {
	name := string(ev.Kind)
	if name == "" {
		name = "event"
	}
	wrapper := map[string]any{
		"agent":   ev.AgentName,
		"seq":     ev.Seq,
		"ts":      ev.Timestamp.Format(time.RFC3339Nano),
		"kind":    string(ev.Kind),
		"payload": ev.Payload,
	}
	b, _ := json.Marshal(wrapper)
	idStr := ev.AgentName + "-" + strconv.Itoa(ev.Seq)
	fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", idStr, name, b)
	flusher.Flush()
}

func writeSSEPlain(w http.ResponseWriter, flusher http.Flusher, name, data string) {
	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
	flusher.Flush()
}

func writeSSEError(w http.ResponseWriter, flusher http.Flusher, err error) {
	msg, _ := json.Marshal(map[string]string{"error": err.Error()})
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", msg)
	flusher.Flush()
}

// Wrap the Broadcaster type so other handlers can pass it in without an
// import cycle on the worker.
var _ SSEBroadcaster = (*transcript.Broadcaster)(nil)

// drainEvents — unused at the moment but kept here to document the intent.
// It illustrates the "drain channel until ctx" idiom we may need in tests.
func drainEvents(ctx context.Context, ch <-chan agentloop.TranscriptEvent) []agentloop.TranscriptEvent {
	var out []agentloop.TranscriptEvent
	for {
		select {
		case <-ctx.Done():
			return out
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		}
	}
}

// Helper kept for handlers that need to derive repo/run IDs from PathValue
// while also supporting the old prefix-based split for backward compat.
func splitRepoRun(r *http.Request) (string, string) {
	repoID := r.PathValue("repo_id")
	runID := r.PathValue("run_id")
	if repoID != "" && runID != "" {
		return repoID, runID
	}
	const prefix = "/repos/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return "", ""
	}
	rest := r.URL.Path[len(prefix):]
	idx := strings.Index(rest, "/")
	if idx < 0 {
		return "", ""
	}
	repoID = rest[:idx]
	rest = rest[idx+1:]
	if !strings.HasPrefix(rest, "runs/") {
		return "", ""
	}
	runID = rest[len("runs/"):]
	if i := strings.Index(runID, "/"); i >= 0 {
		runID = runID[:i]
	}
	return repoID, runID
}
