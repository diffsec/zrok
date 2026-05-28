package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
)

// RunPR clones the repo at the PR head SHA, transitions the run through
// the state machine, fans transcript events to the broadcaster + DBSink,
// posts findings, and fires the GitHub feedback writers.
//
// In PR-4 the in-container agent execution is stubbed: the worker creates a
// container via the Runtime, captures any LogLines it produces (none, in
// the fake-runtime path), and treats a zero-exit-code as success. The full
// workflow.Executor wiring lives in PR-5/6 — for now we record the
// lifecycle in the DB and post placeholder feedback so the end-to-end
// acceptance check (#3) passes.
func RunPR(ctx context.Context, deps *Deps, payload []byte) error {
	var p github.RunPRPayload
	if err := Decode(payload, &p); err != nil {
		return err
	}
	if deps.Stores == nil {
		return errors.New("RunPR: stores not configured")
	}

	// Resolve the repo row (the webhook drops payloads regardless of
	// whether quokka knows the repo yet — fail soft).
	repo, err := deps.Stores.Repos.GetByGitHubID(ctx, p.GitHubRepoID)
	if err != nil {
		return fmt.Errorf("RunPR: repo %d: %w", p.GitHubRepoID, err)
	}

	// Idempotency on (repo, head) — if a run for this head SHA already
	// exists and is past 'queued', skip.
	if existing, err := deps.Stores.Runs.GetByRepoAndHead(ctx, repo.ID, p.HeadSHA); err == nil && existing != nil {
		if !isFinal(existing.Status) {
			deps.Log.Info("RunPR skipped: run already in flight",
				"run_id", existing.ID, "status", existing.Status)
			return nil
		}
		// Already finished — re-runs go through the explicit Re-run UI button
		// in PR-5 (not this code path).
	}

	run := &store.Run{
		RepoID:   repo.ID,
		Trigger:  defaultTrigger(p.Trigger),
		PRNumber: p.PRNumber,
		BaseSHA:  p.BaseSHA,
		HeadSHA:  p.HeadSHA,
		Status:   "queued",
	}
	if err := deps.Stores.Runs.Create(ctx, run); err != nil {
		return fmt.Errorf("RunPR: create run: %w", err)
	}
	appendEvent(ctx, deps, run.ID, "run_queued", map[string]any{
		"pr_number": p.PRNumber,
		"head_sha":  p.HeadSHA,
	})

	// State transition helper.
	advance := func(state string, info map[string]any) {
		_ = deps.Stores.Runs.UpdateStatus(ctx, run.ID, state)
		if info == nil {
			info = map[string]any{}
		}
		info["state"] = state
		appendEvent(ctx, deps, run.ID, "phase_start", info)
	}

	advance("cloning", map[string]any{"pr": p.PRNumber, "head": p.HeadSHA})

	// Acquire an installation token and clone.
	repoDir := filepath.Join(deps.DataRoot, "repos", repo.ID, "workspace")
	var clonedPath string
	if deps.Cloner != nil && deps.GitHub != nil && p.InstallationID != 0 {
		tok, err := deps.GitHub.InstallationToken(ctx, p.InstallationID)
		if err != nil {
			return failRun(ctx, deps, run.ID, "clone_failed", err)
		}
		depth := github.MaxClone(p.CommitsCount)
		clonedPath, err = deps.Cloner.Clone(ctx, tok, p.RepoFullName, p.HeadSHA, depth, repoDir)
		if err != nil {
			return failRun(ctx, deps, run.ID, "clone_failed", err)
		}
	}
	_ = clonedPath

	// Start a Check Run before we begin the heavier work so users see
	// in_progress immediately.
	var checkRunID int64
	if deps.Feedback != nil {
		ownerRepo := splitOwnerRepo(p.RepoFullName)
		if len(ownerRepo) == 2 {
			detailsURL := fmt.Sprintf("%s/repos/%s/runs/%s", strings.TrimRight(deps.BaseURL, "/"), repo.ID, run.ID)
			id, err := deps.Feedback.StartCheckRun(ctx, ownerRepo[0], ownerRepo[1], p.HeadSHA, "quokka", detailsURL, run.ID)
			if err != nil {
				deps.Log.Warn("StartCheckRun failed", "err", err)
			} else {
				checkRunID = id
			}
		}
	}

	advance("indexing", nil)
	// Index step is a no-op in PR-4 — the embedded indexer keeps the
	// per-repo state under /state/<repo_id> and incremental rebuilds happen
	// in the runner container itself.

	advance("running", nil)
	_ = deps.Stores.Runs.MarkStarted(ctx, run.ID, time.Now().UTC())

	// Open a DBSink to persist the transcript file + register the
	// transcripts row at close.
	sink, sinkErr := transcript.NewDBSink(run.ID, "runner", "", deps.DataRoot, deps.Stores)
	if sinkErr != nil {
		deps.Log.Warn("transcript sink unavailable", "err", sinkErr)
	}

	// Watch for cancellation while the container runs.
	containerCtx, cancelContainer := context.WithCancel(ctx)
	defer cancelContainer()

	// Spawn the runner container (or fake) and tail its log lines.
	if deps.Runtime != nil && deps.RunnerImage != "" {
		id, err := deps.Runtime.Create(containerCtx, jobSpecForRun(deps, repo.ID, run.ID, repoDir))
		if err != nil {
			return failRun(ctx, deps, run.ID, "runtime_create_failed", err)
		}
		if err := deps.Runtime.Start(containerCtx, id); err != nil {
			_ = deps.Runtime.Remove(context.Background(), id)
			return failRun(ctx, deps, run.ID, "runtime_start_failed", err)
		}
		logs, err := deps.Runtime.StreamLogs(containerCtx, id)
		if err != nil {
			_ = deps.Runtime.Remove(context.Background(), id)
			return failRun(ctx, deps, run.ID, "runtime_logs_failed", err)
		}

		// Run a parallel cancel-poller — if RunStore.Cancel marks the run as
		// 'cancelled', kill the container and emit a terminal event.
		cancelDone := make(chan struct{})
		go watchForCancel(containerCtx, deps, run.ID, id, cancelContainer, cancelDone)

		drainLogs(containerCtx, deps, run.ID, sink, logs)
		exitCode, err := deps.Runtime.Wait(containerCtx, id)
		_ = deps.Runtime.Remove(context.Background(), id)
		close(cancelDone)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return finalizeCancel(ctx, deps, run.ID, sink)
			}
			return failRun(ctx, deps, run.ID, "runtime_wait_failed", err)
		}
		if exitCode == 137 || exitCode == 143 { // SIGKILL / SIGTERM
			return finalizeCancel(ctx, deps, run.ID, sink)
		}
		if exitCode != 0 {
			return failRun(ctx, deps, run.ID, "runtime_nonzero_exit",
				fmt.Errorf("runner exited with code %d", exitCode))
		}
	}

	if sink != nil {
		if _, err := sink.Close(ctx); err != nil {
			deps.Log.Warn("transcript close failed", "err", err)
		}
	}

	advance("reporting", nil)

	// Fetch findings created during this run for the feedback writers.
	findings, _ := deps.Stores.Findings.ListByRun(ctx, run.ID)
	conclusion := github.ConclusionForFindings(toGitHubFindings(findings))

	settings, _ := deps.Stores.PRFeedback.Get(ctx, repo.ID)
	if settings == nil {
		settings = &store.PRFeedbackSettings{
			RepoID:                repo.ID,
			CheckRunEnabled:       true,
			InlineCommentsEnabled: true,
			SummaryCommentEnabled: true,
		}
	}

	if deps.Feedback != nil {
		ownerRepo := splitOwnerRepo(p.RepoFullName)
		if len(ownerRepo) == 2 {
			title := fmt.Sprintf("quokka: %d finding(s)", len(findings))
			body := summarizeFindings(findings)
			inline := buildInlineComments(findings)
			_, _, _, err := github.PostRunFeedback(ctx, deps.Feedback, settings,
				ownerRepo[0], ownerRepo[1], p.PRNumber, p.HeadSHA, checkRunID, 0,
				conclusion, title, body, inline)
			if err != nil {
				deps.Log.Warn("PostRunFeedback failed", "err", err)
			}
		}
	}

	// Resolve any open findings on the repo whose fingerprints are NOT in
	// the new run.
	seen := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Fingerprint != "" {
			seen = append(seen, f.Fingerprint)
		}
	}
	if _, err := deps.Stores.Findings.AutoResolveMissing(ctx, repo.ID, seen); err != nil {
		deps.Log.Warn("AutoResolveMissing failed", "err", err)
	}

	appendEvent(ctx, deps, run.ID, "phase_end", map[string]any{"state": "reporting"})
	if err := deps.Stores.Runs.MarkCompleted(ctx, run.ID, "completed", time.Now().UTC()); err != nil {
		return err
	}
	appendEvent(ctx, deps, run.ID, "run_completed", map[string]any{"findings": len(findings)})
	return nil
}

func isFinal(status string) bool {
	switch status {
	case "completed", "failed", "cancelled":
		return true
	}
	return false
}

func defaultTrigger(t string) string {
	if t == "" {
		return "webhook"
	}
	return t
}

func splitOwnerRepo(full string) []string {
	parts := strings.SplitN(full, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	return parts
}

func appendEvent(ctx context.Context, deps *Deps, runID, eventType string, payload map[string]any) {
	if deps.Stores == nil || deps.Stores.Events == nil {
		return
	}
	b, _ := json.Marshal(payload)
	_ = deps.Stores.Events.Append(ctx, runID, eventType, string(b))
}

func failRun(ctx context.Context, deps *Deps, runID, category string, err error) error {
	_ = deps.Stores.Runs.UpdateError(ctx, runID, category, err.Error())
	_ = deps.Stores.Runs.MarkCompleted(ctx, runID, "failed", time.Now().UTC())
	appendEvent(ctx, deps, runID, "run_failed", map[string]any{
		"category": category,
		"error":    err.Error(),
	})
	return fmt.Errorf("run %s: %s: %w", runID, category, err)
}

// drainLogs consumes log lines and forwards anything that looks like a
// TranscriptEvent NDJSON line to both the broadcaster (live SSE) and the
// DBSink (durable transcript file + transcripts row).
func drainLogs(ctx context.Context, deps *Deps, runID string, sink *transcript.DBSink, logs <-chan container.LogLine) {
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-logs:
			if !ok {
				return
			}
			if !strings.HasPrefix(line.Text, "{") {
				continue
			}
			ev := parseTranscriptLine(runID, line.Text)
			if deps.Broadcaster != nil {
				deps.Broadcaster.Emit(ev)
			}
			if sink != nil {
				sink.Emit(ev)
			}
		}
	}
}

// watchForCancel polls RunStore every second; when it sees status=cancelled
// it Kills the container and triggers the cancel context. The poll exits on
// cancelDone close (normal container exit) or ctx cancellation.
func watchForCancel(ctx context.Context, deps *Deps, runID, containerID string, cancel context.CancelFunc, cancelDone <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cancelDone:
			return
		case <-ticker.C:
			r, err := deps.Stores.Runs.Get(ctx, runID)
			if err != nil {
				continue
			}
			if r.Status == "cancelled" {
				_ = deps.Runtime.Kill(ctx, containerID)
				cancel()
				return
			}
		}
	}
}

// finalizeCancel writes the terminal run_cancelled event and stamps the run.
func finalizeCancel(ctx context.Context, deps *Deps, runID string, sink *transcript.DBSink) error {
	// Use a fresh context — the caller's ctx is already cancelled.
	bg := context.Background()
	_ = deps.Stores.Runs.MarkCompleted(bg, runID, "cancelled", time.Now().UTC())
	appendEvent(bg, deps, runID, "run_cancelled", map[string]any{"reason": "user_cancelled"})
	if sink != nil {
		_, _ = sink.Close(bg)
	}
	return nil
}
