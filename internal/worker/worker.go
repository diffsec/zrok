// Package worker is the background job processor. It owns the queue, the
// store handles, the agent runtime, and the GitHub feedback client. The
// queue is the only outside-of-process input; everything else is wired at
// construction time.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
	"github.com/diffsec/quokka/internal/worker/jobs"
	"github.com/diffsec/quokka/internal/worker/queue"
)

// ExpectedRunnerImage is set at link time via -ldflags
// "-X github.com/diffsec/quokka/internal/worker.ExpectedRunnerImage=quokka-runner:1.2.3-abc".
// An empty value disables the check (development/test default).
var ExpectedRunnerImage = ""

// Config bundles the runtime knobs.
type Config struct {
	Stores      *store.Stores
	Queue       queue.Queue
	Runtime     container.Runtime
	GitHub      *github.AppAuth
	Cloner      github.Cloner
	Feedback    github.FeedbackClient
	Broadcaster *transcript.Broadcaster
	DataRoot    string
	BaseURL     string
	RunnerImage string
	WorkerID    string
	PollEvery   time.Duration
	Log         *slog.Logger
}

// Worker is the top-level background processor.
type Worker struct {
	cfg      Config
	registry *jobs.Registry
}

// New constructs a Worker. The runner image is checked against
// ExpectedRunnerImage at construction time; mismatch returns an error so the
// caller can fail fast.
func New(cfg Config) (*Worker, error) {
	if cfg.Stores == nil {
		return nil, errors.New("worker: Stores required")
	}
	if cfg.Queue == nil {
		return nil, errors.New("worker: Queue required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = time.Second
	}
	if cfg.WorkerID == "" {
		cfg.WorkerID = "worker"
	}
	if ExpectedRunnerImage != "" && cfg.RunnerImage != "" && ExpectedRunnerImage != cfg.RunnerImage {
		return nil, errors.New("worker: runner image tag mismatch: expected " +
			ExpectedRunnerImage + ", got " + cfg.RunnerImage)
	}
	return &Worker{cfg: cfg, registry: jobs.Default()}, nil
}

// Registry exposes the underlying registry for tests.
func (w *Worker) Registry() *jobs.Registry { return w.registry }

// Run is the main loop. Blocks until ctx is done.
func (w *Worker) Run(ctx context.Context) error {
	w.cfg.Log.Info("worker starting",
		"worker_id", w.cfg.WorkerID,
		"runner_image", w.cfg.RunnerImage,
		"expected_runner_image", ExpectedRunnerImage,
	)
	t := time.NewTicker(w.cfg.PollEvery)
	defer t.Stop()
	for {
		if err := w.tickOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.cfg.Log.Warn("worker tick", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// tickOnce claims one job and runs its handler.
func (w *Worker) tickOnce(ctx context.Context) error {
	job, err := w.cfg.Queue.Dequeue(ctx, w.cfg.WorkerID)
	if err != nil {
		return err
	}
	if job == nil {
		return nil
	}
	return w.dispatch(ctx, job)
}

// dispatch looks up the handler and runs it; complete/fail the job at the end.
func (w *Worker) dispatch(ctx context.Context, job *queue.Job) error {
	h, err := w.registry.Get(job.Type)
	if err != nil {
		_ = w.cfg.Queue.Fail(ctx, job.ID, err.Error(), false)
		return err
	}
	deps := w.deps()
	if hErr := h(ctx, deps, []byte(job.PayloadJSON)); hErr != nil {
		w.cfg.Log.Warn("job failed", "type", job.Type, "id", job.ID, "err", hErr)
		// Runs are non-retryable per locked decisions; other job types
		// retry up to 3 times.
		retry := job.Type != "RunPR" && job.Type != "RunManual" && job.Attempts < 3
		_ = w.cfg.Queue.Fail(ctx, job.ID, hErr.Error(), retry)
		return hErr
	}
	return w.cfg.Queue.Complete(ctx, job.ID)
}

// deps freezes the per-tick Deps from the worker config.
func (w *Worker) deps() *jobs.Deps {
	return &jobs.Deps{
		Stores:      w.cfg.Stores,
		Runtime:     w.cfg.Runtime,
		GitHub:      w.cfg.GitHub,
		Cloner:      w.cfg.Cloner,
		Feedback:    w.cfg.Feedback,
		Broadcaster: w.cfg.Broadcaster,
		DataRoot:    w.cfg.DataRoot,
		BaseURL:     w.cfg.BaseURL,
		RunnerImage: w.cfg.RunnerImage,
		WorkerID:    w.cfg.WorkerID,
		Log:         w.cfg.Log,
	}
}

// DispatchOne is a test helper that synchronously runs the handler for one
// job from the queue. Returns nil if the queue is empty.
func (w *Worker) DispatchOne(ctx context.Context) error {
	job, err := w.cfg.Queue.Dequeue(ctx, w.cfg.WorkerID)
	if err != nil {
		return err
	}
	if job == nil {
		return nil
	}
	return w.dispatch(ctx, job)
}
