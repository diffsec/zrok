package jobs_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/app"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/llm/fake"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	"github.com/diffsec/quokka/internal/storerpc"
	"github.com/diffsec/quokka/internal/transcript"
	"github.com/diffsec/quokka/internal/worker"
	"github.com/diffsec/quokka/internal/worker/jobs"
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
	if finishIdx >= reviewIdx || reviewIdx >= summaryIdx {
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

// sidecarRuntime is a test Runtime that drives an in-process sidecar
// against the worker's real RPC socket. When Create is called it
// captures the JobSpec, when Start is called it spawns a goroutine that
// dials the socket and calls app.RunSidecar with a fake LLM provider.
//
// This is the new "real end-to-end" runner: webhook → worker → real
// RPC server → real workflow.Executor (in-process sidecar) → real
// tool registry → real DB rows.
type sidecarRuntime struct {
	mu      sync.Mutex
	nextID  int
	spec    *container.ContainerSpec
	specCh  chan struct{}
	exit    chan int
	logsR   *io.PipeReader
	logsW   *io.PipeWriter
	killed  bool
	removed bool

	t        *testing.T
	provider llm.Provider
}

func newSidecarRuntime(t *testing.T, p llm.Provider) *sidecarRuntime {
	r, w := io.Pipe()
	return &sidecarRuntime{
		specCh:   make(chan struct{}),
		exit:     make(chan int, 1),
		logsR:    r,
		logsW:    w,
		t:        t,
		provider: p,
	}
}

func (s *sidecarRuntime) Create(ctx context.Context, spec container.ContainerSpec) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := "sidecar-1"
	s.spec = &spec
	close(s.specCh)
	return id, nil
}

func (s *sidecarRuntime) Start(ctx context.Context, id string) error {
	// Spawn the sidecar in-process: decode the JobSpec from the
	// container spec, dial the RPC socket the worker set up, and run
	// the executor. NDJSON output is piped to the StreamLogs channel
	// so the worker's drainLogs ingests it exactly as it would from a
	// real container.
	s.mu.Lock()
	jsBytes := s.spec.JobSpecJSON
	var sm container.SocketMount
	if len(s.spec.SocketBindMounts) > 0 {
		sm = s.spec.SocketBindMounts[0]
	}
	s.mu.Unlock()

	var spec jobs.JobSpec
	if err := json.Unmarshal(jsBytes, &spec); err != nil {
		return err
	}
	// The sidecar inside the real container would dial
	// /var/run/quokka.sock; outside, dial the host socket directly.
	hostSocket := sm.HostPath
	if hostSocket == "" {
		hostSocket = spec.RPCSocket
	}

	client, err := storerpc.Dial(hostSocket, spec.RPCToken)
	if err != nil {
		return err
	}

	factory := app.ProviderFactory(func(*agent.ModelConfig) (llm.Provider, error) {
		return s.provider, nil
	})

	go func() {
		defer func() { _ = client.Close() }()
		defer func() { _ = s.logsW.Close() }()
		err := app.RunSidecar(ctx, &spec, client, factory, s.logsW)
		code := 0
		if err != nil {
			s.t.Logf("sidecarRuntime: RunSidecar err=%v", err)
			code = 1
		}
		select {
		case s.exit <- code:
		default:
		}
	}()
	return nil
}

func (s *sidecarRuntime) StreamLogs(ctx context.Context, id string) (<-chan container.LogLine, error) {
	out := make(chan container.LogLine, 16)
	go func() {
		defer close(out)
		br := bufio.NewReader(s.logsR)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				select {
				case out <- container.LogLine{Stream: "stdout", Text: strings.TrimRight(line, "\n")}:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return out, nil
}

func (s *sidecarRuntime) Wait(ctx context.Context, id string) (int, error) {
	select {
	case c := <-s.exit:
		return c, nil
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

func (s *sidecarRuntime) Kill(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killed = true
	select {
	case s.exit <- 137:
	default:
	}
	return nil
}

func (s *sidecarRuntime) Remove(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed = true
	return nil
}

// TestRunPRRealEndToEndWithInProcessSidecar exercises the full
// pipeline with no canned data: the worker stands up a real RPC
// server, a sidecarRuntime drives app.RunSidecar in-process against a
// fake LLM scripted to call finding_create, and we assert that the
// finding row landed via the RPC path and the feedback writers fired.
func TestRunPRRealEndToEndWithInProcessSidecar(t *testing.T) {
	stores, dir := openTestStores(t)
	ctx := context.Background()

	org := &store.Org{Name: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("Orgs.Create: %v", err)
	}
	install := &store.Installation{
		OrgID:                org.ID,
		GitHubInstallationID: 77,
		AccountLogin:         "acme",
		AccountType:          "Organization",
		TargetType:           "Organization",
	}
	if err := stores.Installations.Create(ctx, install); err != nil {
		t.Fatalf("Installations.Create: %v", err)
	}
	// classify the repo so the test-agent's project-types applicability
	// matches.
	cls := project.ProjectClassification{Types: []project.ProjectType{project.TypeWebApp}}
	clsJSON, _ := json.Marshal(cls)
	repo := &store.Repository{
		OrgID:              org.ID,
		InstallationID:     install.ID,
		GitHubRepoID:       77,
		FullName:           "acme/widget2",
		DefaultBranch:      "main",
		ClassificationJSON: string(clsJSON),
	}
	if err := stores.Repos.Create(ctx, repo); err != nil {
		t.Fatalf("Repos.Create: %v", err)
	}

	// Seed a workflow row that names a single agent. The worker will
	// resolve this and embed it into the JobSpec.
	wfYAML := `
name: test
version: 1
phases:
  - name: reporting
    mode: sequential
    agents:
      - test-agent
`
	wf := &store.Workflow{OrgID: org.ID, RepoID: repo.ID, Name: "test"}
	if err := stores.Workflows.Create(ctx, wf); err != nil {
		t.Fatalf("Workflows.Create: %v", err)
	}
	ver := &store.WorkflowVersion{WorkflowID: wf.ID, YAML: wfYAML, CreatedBy: ""}
	if err := stores.Workflows.NewVersion(ctx, ver); err != nil {
		t.Fatalf("Workflows.NewVersion: %v", err)
	}
	if err := stores.Workflows.SetActiveVersion(ctx, wf.ID, ver.ID); err != nil {
		t.Fatalf("SetActiveVersion: %v", err)
	}

	// Set the provider env vars the sidecar's NewEnvProviderFactory
	// would consume in prod. The sidecarRuntime bypasses the env-driven
	// factory in favour of returning the fake provider directly, but
	// the worker still injects QUOKKA_PROVIDER_* — we leave the env
	// clean so we exercise the fallback resolution path.
	t.Setenv("ANTHROPIC_API_KEY", "test-key")

	// Fake LLM: one turn that calls finding_create, second turn that
	// produces a text reply and ends. Drives one agent.
	findingArgs := `{"title":"hardcoded creds","severity":"high","file":"main.go","line_start":11,"description":"oops"}`
	turn1 := []llm.Event{
		{Kind: llm.EventToolCallStart, ToolUseID: "tu1", ToolName: "finding_create"},
		{Kind: llm.EventToolCallDelta, ToolUseID: "tu1", InputDelta: findingArgs},
		{Kind: llm.EventToolCallEnd, ToolUseID: "tu1"},
		{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
	}
	turn2 := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "done"},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	provider := fake.New("fake-anthropic", turn1, turn2)

	// Patch the test-agent into the registry path the worker reads.
	// We do this by writing a temporary YAML into a path the in-test
	// agent registry can see. Easier: just rely on agent.GetBuiltinAgent
	// — the worker's resolveAgents calls GetBuiltinAgents(), and our
	// agent name "test-agent" won't be in the registry. That's fine
	// because the sidecar's buildAgentLookup falls through to the
	// spec.Agents map first. But the worker only puts built-in agents
	// in the spec. To get "test-agent" into the spec, we register it
	// in the test by writing a workflow that names a built-in agent.
	// Use review-agent since it's in the registry.
	_ = wfYAML
	if a := agent.GetBuiltinAgent("review-agent"); a == nil {
		t.Fatalf("expected review-agent to be in built-in registry")
	}
	// Reseed the workflow YAML to use review-agent.
	realYAML := `
name: test
version: 1
phases:
  - name: reporting
    mode: sequential
    agents:
      - review-agent
`
	// Update the workflow version's yaml directly: insert a new version.
	ver2 := &store.WorkflowVersion{WorkflowID: wf.ID, YAML: realYAML, CreatedBy: ""}
	if err := stores.Workflows.NewVersion(ctx, ver2); err != nil {
		t.Fatalf("Workflows.NewVersion v2: %v", err)
	}
	if err := stores.Workflows.SetActiveVersion(ctx, wf.ID, ver2.ID); err != nil {
		t.Fatalf("SetActiveVersion v2: %v", err)
	}

	cl := &fakeCloner{}
	fb := &fakeFeedback{}
	rt := newSidecarRuntime(t, provider)
	bcast := transcript.NewBroadcaster()

	q := queue.NewSQLQueue(stores.Jobs)

	w, err := worker.New(worker.Config{
		Stores:      stores,
		Queue:       q,
		Runtime:     rt,
		GitHub:      seededAuth(t, 77),
		Cloner:      cl,
		Feedback:    fb,
		Broadcaster: bcast,
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
		InstallationID: 77,
		RepoFullName:   "acme/widget2",
		GitHubRepoID:   77,
		PRNumber:       8,
		BaseSHA:        "b",
		HeadSHA:        "h2",
		Trigger:        "pr_opened",
	})
	if _, _, err := q.Enqueue(ctx, &queue.Job{
		Type:           "RunPR",
		PayloadJSON:    string(payload),
		IdempotencyKey: "run:77:8:h2",
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.DispatchOne(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DispatchOne: %v", err)
		}
	case <-time.After(20 * time.Second):
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

	// The finding lands in the DB via the RPC path. Assert by run.
	findings, err := stores.Findings.ListByRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("Findings.ListByRun: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding via RPC, got %d", len(findings))
	}
	f := findings[0]
	if f.Title != "hardcoded creds" || f.Severity != "high" || f.File != "main.go" {
		t.Errorf("finding shape mismatch: %+v", f)
	}
	if f.CreatedBy != "review-agent" {
		t.Errorf("expected created_by=review-agent, got %q", f.CreatedBy)
	}

	// Feedback writers ran in order: start_check_run, then finish/review/summary.
	if len(fb.calls) == 0 || fb.calls[0] != "start_check_run" {
		t.Fatalf("expected start_check_run first, got %v", fb.calls)
	}
	saw := map[string]bool{}
	for _, c := range fb.calls {
		saw[c] = true
	}
	if !saw["finish_check_run"] || !saw["post_review"] || !saw["upsert_summary_comment"] {
		t.Errorf("expected all writers; got %v", fb.calls)
	}

	// Transcript row should exist; verify the file has the executor's
	// NDJSON sequence (agent_start, tool_call, tool_result at minimum).
	trs, err := stores.Transcripts.List(ctx, run.ID)
	if err != nil || len(trs) == 0 {
		t.Fatalf("expected a transcript row; got %v err=%v", trs, err)
	}
	path := strings.TrimPrefix(trs[0].StorageURI, "file://")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	body := string(b)
	for _, want := range []string{"agent_start", "tool_call", "tool_result"} {
		if !strings.Contains(body, want) {
			t.Errorf("transcript missing %q; body=%s", want, body)
		}
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
