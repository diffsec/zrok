package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
	"github.com/diffsec/quokka/internal/worker"
	"github.com/diffsec/quokka/internal/worker/queue"
	"github.com/spf13/cobra"
)

func newWorkerCmd() *cobra.Command {
	var (
		runnerImage string
		workerID    string
		baseURL     string
		useDocker   bool
	)
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run the background job worker",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWorker(cmd.Context(), workerID, runnerImage, baseURL, useDocker)
		},
	}
	cmd.Flags().StringVar(&runnerImage, "runner-image", os.Getenv("QUOKKA_RUNNER_IMAGE"),
		"Runner container image tag (env QUOKKA_RUNNER_IMAGE)")
	cmd.Flags().StringVar(&workerID, "worker-id", os.Getenv("HOSTNAME"),
		"Worker identity tag for queue claim attribution")
	cmd.Flags().StringVar(&baseURL, "base-url", os.Getenv("QUOKKA_BASE_URL"),
		"Externally visible base URL for Check Run details (env QUOKKA_BASE_URL)")
	cmd.Flags().BoolVar(&useDocker, "use-docker", true,
		"Connect to Docker for the container runtime. Disable in environments without Docker.")
	return cmd
}

func runWorker(ctx context.Context, workerID, runnerImage, baseURL string, useDocker bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if globals.DSN == "" {
		return fmt.Errorf("--dsn or QUOKKA_DSN is required")
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	stores, err := store.Open(ctx, store.Config{DSN: globals.DSN, DataRoot: globals.DataRoot})
	if err != nil {
		return fmt.Errorf("open stores: %w", err)
	}
	defer func() { _ = stores.Close() }()

	var rt container.Runtime
	if useDocker {
		dr, err := container.NewDockerRuntime()
		if err != nil {
			log.Warn("docker runtime unavailable; running without container backend", "err", err)
		} else {
			rt = dr
			defer func() { _ = dr.Close() }()
		}
	}

	var auth *github.AppAuth
	if appIDStr := os.Getenv("QUOKKA_GITHUB_APP_ID"); appIDStr != "" {
		appID, err := strconv.ParseInt(appIDStr, 10, 64)
		if err != nil {
			return fmt.Errorf("parse QUOKKA_GITHUB_APP_ID: %w", err)
		}
		keyPath := os.Getenv("QUOKKA_GITHUB_APP_PRIVATE_KEY_FILE")
		auth = github.NewAppAuth(appID, keyPath)
	}

	bcast := transcript.NewBroadcaster()
	q := queue.NewSQLQueue(stores.Jobs)

	cfg := worker.Config{
		Stores:      stores,
		Queue:       q,
		Runtime:     rt,
		GitHub:      auth,
		Cloner:      &github.GoGitCloner{},
		Broadcaster: bcast,
		DataRoot:    globals.DataRoot,
		BaseURL:     baseURL,
		RunnerImage: runnerImage,
		WorkerID:    workerID,
		Log:         log,
	}
	// Feedback uses the GitHub App auth — installation IDs vary per repo,
	// so PR-5 will introduce a per-install factory. For PR-4 we leave
	// Feedback nil when running against a real worker; the run_pr handler
	// is tested with a fake Feedback in jobs/run_pr_test.go.

	w, err := worker.New(cfg)
	if err != nil {
		return err
	}

	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return w.Run(sigCtx)
}

