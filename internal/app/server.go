package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/diffsec/quokka/internal/agentloop/tools"
	githubpkg "github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
	"github.com/diffsec/quokka/internal/web"
	"github.com/diffsec/quokka/internal/web/handlers"
	"github.com/diffsec/quokka/internal/worker/queue"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	var (
		addr    string
		baseURL string
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the HTTP web server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(cmd.Context(), addr, baseURL)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "Listen address (e.g. :8080)")
	cmd.Flags().StringVar(&baseURL, "base-url", os.Getenv("QUOKKA_BASE_URL"),
		"Externally visible base URL for OAuth callbacks (env QUOKKA_BASE_URL)")
	return cmd
}

func runServer(ctx context.Context, addr, baseURL string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if globals.DSN == "" {
		return fmt.Errorf("--dsn or QUOKKA_DSN is required")
	}
	if baseURL == "" {
		return fmt.Errorf("--base-url or QUOKKA_BASE_URL is required")
	}

	stores, err := store.Open(ctx, store.Config{DSN: globals.DSN, DataRoot: globals.DataRoot})
	if err != nil {
		return fmt.Errorf("open stores: %w", err)
	}
	defer func() { _ = stores.Close() }()

	clientID := os.Getenv("QUOKKA_GITHUB_APP_CLIENT_ID")
	clientSecret := os.Getenv("QUOKKA_GITHUB_APP_CLIENT_SECRET")
	orgLogin := os.Getenv("QUOKKA_GITHUB_ORG")
	adminLogins := splitAndTrim(os.Getenv("QUOKKA_ADMIN_LOGINS"))

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	webhookSecret := os.Getenv("QUOKKA_GITHUB_WEBHOOK_SECRET")
	q := queue.NewSQLQueue(stores.Jobs)
	enqueueFn := func(ctx context.Context, jobType string, payload any, key string) (bool, error) {
		b, err := json.Marshal(payload)
		if err != nil {
			return false, err
		}
		_, ins, err := q.Enqueue(ctx, &queue.Job{
			Type:           jobType,
			PayloadJSON:    string(b),
			IdempotencyKey: key,
		})
		return ins, err
	}

	// Wire optional dependencies that PR-5 introduced: in-memory transcript
	// broadcaster (live SSE), agent-tool registry (agent editor's tools
	// multiselect), and a GitHub App authenticator for the commit-back PR
	// feature. Each is nil-safe; the handlers degrade gracefully.
	broadcaster := transcript.NewBroadcaster()
	toolReg := tools.Default()
	var appAuth *githubpkg.AppAuth
	if appIDStr := os.Getenv("QUOKKA_GITHUB_APP_ID"); appIDStr != "" {
		if id, err := strconv.ParseInt(appIDStr, 10, 64); err == nil {
			keyPath := os.Getenv("QUOKKA_GITHUB_APP_PRIVATE_KEY_FILE")
			if keyPath != "" {
				appAuth = githubpkg.NewAppAuth(id, keyPath)
			}
		}
	}

	srv := web.NewServer(web.Config{
		Addr:           addr,
		BaseURL:        baseURL,
		OrgLogin:       orgLogin,
		AdminLogins:    adminLogins,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		SecureCookies:  false, // computed from BaseURL inside NewServer
		GitHub:         handlers.NewHTTPGitHubClient(clientID, clientSecret, "", ""),
		Stores:         stores,
		Log:            log,
		WebhookSecret:  webhookSecret,
		WebhookEnqueue: enqueueFn,
		Broadcaster:    broadcaster,
		ToolRegistry:   toolReg,
		AppAuth:        appAuth,
		DataRoot:       globals.DataRoot,
	})

	// Shutdown on SIGINT/SIGTERM.
	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()
	select {
	case <-sigCtx.Done():
		log.Info("shutdown signal received")
		sdCtx, sdCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer sdCancel()
		if err := srv.Shutdown(sdCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
