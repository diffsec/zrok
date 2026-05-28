package jobs_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	"github.com/diffsec/quokka/internal/transcript"
	"github.com/diffsec/quokka/internal/worker"
	"github.com/diffsec/quokka/internal/worker/queue"
)

func randB64Key(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func openTestStores(t *testing.T) (*store.Stores, string) {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "test.db")
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	stores, err := store.Open(context.Background(), store.Config{DSN: dsn, DataRoot: dir})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	if err := migrations.Up(migrations.DialectSQLite, stores.DB); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return stores, dir
}

type fakeCloner struct {
	mu       sync.Mutex
	calls    int
	cloneDir string
}

func (f *fakeCloner) Clone(ctx context.Context, tok, repo, ref string, depth int, dest string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.cloneDir = dest
	return dest, nil
}

type fakeFeedback struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeFeedback) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}
func (f *fakeFeedback) StartCheckRun(ctx context.Context, _, _, _, _, _, _ string) (int64, error) {
	f.record("start_check_run")
	return 1, nil
}
func (f *fakeFeedback) FinishCheckRun(ctx context.Context, _, _ string, _ int64, _, _, _ string) error {
	f.record("finish_check_run")
	return nil
}
func (f *fakeFeedback) PostReview(ctx context.Context, _, _ string, _ int, _, _ string, _ []github.ReviewComment) (int64, error) {
	f.record("post_review")
	return 2, nil
}
func (f *fakeFeedback) DismissReview(ctx context.Context, _, _ string, _ int, _ int64) error {
	f.record("dismiss_review")
	return nil
}
func (f *fakeFeedback) UpsertSummaryComment(ctx context.Context, _, _ string, _ int, _ string) (int64, error) {
	f.record("upsert_summary_comment")
	return 3, nil
}

func TestRunPREndToEndWithFakes(t *testing.T) {
	stores, dir := openTestStores(t)
	ctx := context.Background()

	// Seed org + installation + repo.
	org := &store.Org{Name: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("Orgs.Create: %v", err)
	}
	install := &store.Installation{
		OrgID:                org.ID,
		GitHubInstallationID: 99,
		AccountLogin:         "acme",
		AccountType:          "Organization",
		TargetType:           "Organization",
	}
	if err := stores.Installations.Create(ctx, install); err != nil {
		t.Fatalf("Installations.Create: %v", err)
	}
	repo := &store.Repository{
		OrgID:          org.ID,
		InstallationID: install.ID,
		GitHubRepoID:   42,
		FullName:       "acme/widget",
		DefaultBranch:  "main",
		Private:        true,
	}
	if err := stores.Repos.Create(ctx, repo); err != nil {
		t.Fatalf("Repos.Create: %v", err)
	}

	cl := &fakeCloner{}
	fb := &fakeFeedback{}
	rt := container.NewFakeRuntime()
	bcast := transcript.NewBroadcaster()
	log := slog.Default()

	q := queue.NewSQLQueue(stores.Jobs)

	w, err := worker.New(worker.Config{
		Stores:      stores,
		Queue:       q,
		Runtime:     rt,
		GitHub:      seededAuth(t, 99),
		Cloner:      cl,
		Feedback:    fb,
		Broadcaster: bcast,
		DataRoot:    dir,
		BaseURL:     "http://localhost:8080",
		RunnerImage: "quokka-runner:test",
		WorkerID:    "test-worker",
		Log:         log,
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}

	// Enqueue a RunPR.
	payload, _ := json.Marshal(github.RunPRPayload{
		InstallationID: 99,
		RepoFullName:   "acme/widget",
		GitHubRepoID:   42,
		PRNumber:       7,
		BaseSHA:        "base-sha",
		HeadSHA:        "head-sha",
		Trigger:        "pr_opened",
	})
	if _, _, err := q.Enqueue(ctx, &queue.Job{
		Type:           "RunPR",
		PayloadJSON:    string(payload),
		IdempotencyKey: "run:42:7:head-sha",
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Drive the runtime — the fake container exits immediately with code 0.
	// Once Create fires, queue an NDJSON transcript line and a finding linked
	// to the eventual run, then SetExitCode to release Wait().
	done := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := rt.LastSpec(); ok {
				// Discover the run ID that the worker just created.
				runs, _ := stores.Runs.List(context.Background(), repo.ID, 1, 0)
				runID := ""
				if len(runs) > 0 {
					runID = runs[0].ID
				}
				// Queue an NDJSON event so the DBSink writes a transcript line.
				rt.QueueLog("fake-1", "stdout", `{"run_id":"`+runID+`","agent_name":"runner","seq":1,"ts":"2024-01-01T00:00:00Z","kind":"agent_start","payload":{"agent":"runner"}}`)
				// Link a finding to the run so PostReview has something to send.
				_ = stores.Findings.Create(context.Background(), &store.FindingRow{
					RepoID:      repo.ID,
					RunID:       runID,
					Title:       "test issue",
					Severity:    "high",
					Fingerprint: "fp-1",
					File:        "main.go",
					LineStart:   3,
					CreatedBy:   "security-agent",
				})
				// Give drainLogs a tick to process the queued line.
				time.Sleep(100 * time.Millisecond)
				rt.SetExitCode("fake-1", 0)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	go func() { done <- w.DispatchOne(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DispatchOne: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("DispatchOne timed out")
	}

	runs, err := stores.Runs.List(ctx, repo.ID, 10, 0)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs list: %v len=%d", err, len(runs))
	}
	run := runs[0]
	if run.Status != "completed" {
		t.Fatalf("expected status=completed, got %q (err_category=%q err=%q)",
			run.Status, run.ErrorCategory, run.ErrorMessage)
	}

	// Transcripts row must exist with a non-empty storage URI.
	trs, err := stores.Transcripts.List(ctx, run.ID)
	if err != nil {
		t.Fatalf("Transcripts.List: %v", err)
	}
	if len(trs) == 0 {
		t.Fatalf("expected a transcripts row, got 0")
	}
	if !strings.HasPrefix(trs[0].StorageURI, "file://") {
		t.Fatalf("expected file:// storage URI, got %q", trs[0].StorageURI)
	}

	// timeline_events should include phase_start and run_completed.
	events, err := stores.Events.Stream(ctx, run.ID, run.CreatedAt.Add(-1))
	if err != nil {
		t.Fatalf("Events.Stream: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected timeline events, got 0")
	}
	kinds := map[string]bool{}
	for _, e := range events {
		kinds[e.EventType] = true
	}
	if !kinds["run_queued"] || !kinds["phase_start"] || !kinds["run_completed"] {
		t.Fatalf("expected run_queued+phase_start+run_completed in events; got %v",
			eventKinds(events))
	}

	// All three feedback writers should have fired in order:
	// start_check_run (run start) -> finish_check_run -> post_review -> upsert_summary_comment.
	if fb.calls[0] != "start_check_run" {
		t.Fatalf("expected start_check_run first, got %q (calls=%v)", fb.calls[0], fb.calls)
	}
	idx := func(name string) int {
		for i, c := range fb.calls {
			if c == name {
				return i
			}
		}
		return -1
	}
	finishIdx := idx("finish_check_run")
	reviewIdx := idx("post_review")
	summaryIdx := idx("upsert_summary_comment")
	if finishIdx == -1 || reviewIdx == -1 || summaryIdx == -1 {
		t.Fatalf("missing writer: calls=%v", fb.calls)
	}
	if !(finishIdx < reviewIdx && reviewIdx < summaryIdx) {
		t.Fatalf("writer order wrong: calls=%v (want finish < review < summary)", fb.calls)
	}

	// Cloner was called once.
	if cl.calls != 1 {
		t.Fatalf("expected 1 clone call, got %d", cl.calls)
	}
	if !strings.Contains(cl.cloneDir, repo.ID) {
		t.Fatalf("expected clone dir to contain repo id %q, got %q", repo.ID, cl.cloneDir)
	}
}

func TestRunPRCancelKillsContainerAndEmitsTerminalEvent(t *testing.T) {
	stores, dir := openTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	install := &store.Installation{
		OrgID:                org.ID,
		GitHubInstallationID: 1,
		AccountLogin:         "acme",
		AccountType:          "Organization",
		TargetType:           "Organization",
	}
	_ = stores.Installations.Create(ctx, install)
	repo := &store.Repository{OrgID: org.ID, InstallationID: install.ID, GitHubRepoID: 50, FullName: "a/b"}
	_ = stores.Repos.Create(ctx, repo)

	cl := &fakeCloner{}
	rt := container.NewFakeRuntime()
	q := queue.NewSQLQueue(stores.Jobs)
	w, err := worker.New(worker.Config{
		Stores:      stores,
		Queue:       q,
		Runtime:     rt,
		GitHub:      seededAuth(t, 1),
		Cloner:      cl,
		Broadcaster: transcript.NewBroadcaster(),
		DataRoot:    dir,
		BaseURL:     "http://localhost:8080",
		RunnerImage: "quokka-runner:test",
		WorkerID:    "test-worker",
		Log:         slog.Default(),
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	payload, _ := json.Marshal(github.RunPRPayload{
		InstallationID: 1,
		RepoFullName:   "a/b",
		GitHubRepoID:   50,
		PRNumber:       1,
		HeadSHA:        "h",
	})
	_, _, _ = q.Enqueue(ctx, &queue.Job{
		Type:           "RunPR",
		PayloadJSON:    string(payload),
		IdempotencyKey: "run:50:1:h",
	})

	done := make(chan error, 1)
	go func() { done <- w.DispatchOne(ctx) }()

	// Once the container is created, mark the run cancelled. The
	// watchForCancel goroutine should call Runtime.Kill, the container
	// stops with code 137, and finalizeCancel writes 'run_cancelled'.
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := rt.LastSpec(); ok {
				// Cancel via store.
				runs, _ := stores.Runs.List(context.Background(), repo.ID, 1, 0)
				if len(runs) > 0 {
					_ = stores.Runs.Cancel(context.Background(), runs[0].ID)
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DispatchOne: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("cancel path timed out")
	}

	if !rt.Killed("fake-1") {
		t.Fatalf("expected container fake-1 to be killed")
	}
	runs, _ := stores.Runs.List(ctx, repo.ID, 1, 0)
	if len(runs) != 1 || runs[0].Status != "cancelled" {
		t.Fatalf("expected run status=cancelled, got %#v", runs)
	}
	events, _ := stores.Events.Stream(ctx, runs[0].ID, runs[0].CreatedAt.Add(-1))
	saw := false
	for _, e := range events {
		if e.EventType == "run_cancelled" {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("expected run_cancelled event; got %v", eventKinds(events))
	}
}

func TestRunPRRedeliveryIsNoOpWhenInFlight(t *testing.T) {
	stores, dir := openTestStores(t)
	_ = dir
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{
		OrgID:        org.ID,
		GitHubRepoID: 99,
		FullName:     "x/y",
	}
	_ = stores.Repos.Create(ctx, repo)

	q := queue.NewSQLQueue(stores.Jobs)
	payload, _ := json.Marshal(github.RunPRPayload{
		GitHubRepoID: 99,
		PRNumber:     1,
		HeadSHA:      "h",
	})
	_, ins1, err := q.Enqueue(ctx, &queue.Job{
		Type:           "RunPR",
		PayloadJSON:    string(payload),
		IdempotencyKey: "run:99:1:h",
	})
	if err != nil || !ins1 {
		t.Fatalf("first enqueue: ins=%v err=%v", ins1, err)
	}
	_, ins2, err := q.Enqueue(ctx, &queue.Job{
		Type:           "RunPR",
		PayloadJSON:    string(payload),
		IdempotencyKey: "run:99:1:h",
	})
	if err != nil {
		t.Fatalf("second enqueue: %v", err)
	}
	if ins2 {
		t.Fatalf("expected second enqueue to be a no-op (inserted=false), got %v", ins2)
	}
}

func seededAuth(t *testing.T, installID int64) *github.AppAuth {
	t.Helper()
	a := github.NewAppAuth(1, "")
	github.SeedInstallationToken(a, installID, "tok", farFuture())
	return a
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }

func eventKinds(events []*store.TimelineEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventType)
	}
	return out
}
