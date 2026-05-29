// Package web hosts the HTTP server for the SaaS web UI.
package web

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/agentloop/tools"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/handlers"
	"github.com/diffsec/quokka/internal/web/middleware"
)

//go:embed static
var staticFS embed.FS

// Config bundles the runtime knobs server construction needs.
type Config struct {
	Addr           string
	BaseURL        string
	OrgLogin       string
	AdminLogins    []string
	ClientID       string
	ClientSecret   string
	SecureCookies  bool
	GitHub         handlers.GitHubClient
	Stores         *store.Stores
	Log            *slog.Logger
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	StaticOverride fs.FS // tests can swap the embed for a no-op
	// WebhookSecret is the GitHub App webhook signing secret. When set, the
	// POST /webhooks/github route is wired with HMAC verification.
	WebhookSecret string
	// WebhookEnqueue is called by the webhook dispatch to schedule a job.
	// Typically wired to a queue.Queue.Enqueue closure.
	WebhookEnqueue github.EnqueueFunc
	// Broadcaster is the transcript broadcaster used by the SSE handler.
	// nil disables live transcript fan-out (completed runs still replay).
	Broadcaster handlers.SSEBroadcaster
	// ToolRegistry powers the agent editor's tools-allowed multiselect.
	// nil is fine — the field is rendered as a free-form text input.
	ToolRegistry *tools.Registry
	// AppAuth is the GitHub App authenticator. Required for the agent
	// editor's commit-back PR feature; nil disables that button.
	AppAuth *github.AppAuth
	// DataRoot is needed to read transcript files for completed runs.
	DataRoot string
}

// Server wraps the http.Server and exposes Start / Shutdown.
type Server struct {
	cfg     Config
	handler http.Handler
	server  *http.Server
}

// NewServer builds the mux and wraps it in the standard middleware stack.
func NewServer(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.SecureCookies == false && cfg.BaseURL != "" {
		cfg.SecureCookies = strings.HasPrefix(cfg.BaseURL, "https://")
	}

	mux := http.NewServeMux()

	// Static files.
	var sfs fs.FS
	if cfg.StaticOverride != nil {
		sfs = cfg.StaticOverride
	} else {
		sub, err := fs.Sub(staticFS, "static")
		if err != nil {
			panic(err) // embed guarantees this directory exists
		}
		sfs = sub
	}
	mux.Handle("/static/", secureHeaders(http.StripPrefix("/static/", http.FileServer(http.FS(sfs)))))

	mux.HandleFunc("/healthz", handlers.Healthz)

	// GitHub webhook receiver.
	if cfg.WebhookSecret != "" {
		wh := &github.WebhookHandler{
			Secret:  cfg.WebhookSecret,
			Stores:  cfg.Stores,
			Enqueue: cfg.WebhookEnqueue,
		}
		mux.Handle("/webhooks/github", wh)
	}

	auth := handlers.NewAuthHandler(handlers.AuthConfig{
		ClientID:      cfg.ClientID,
		ClientSecret:  cfg.ClientSecret,
		OrgLogin:      cfg.OrgLogin,
		AdminLogins:   cfg.AdminLogins,
		BaseURL:       cfg.BaseURL,
		SecureCookies: cfg.SecureCookies,
		GitHub:        cfg.GitHub,
		Stores:        cfg.Stores,
		Log:           cfg.Log,
	})
	mux.HandleFunc("/login", auth.LoginPage)
	mux.HandleFunc("/login/start", auth.LoginStart)
	mux.HandleFunc("/oauth/callback", auth.Callback)
	mux.HandleFunc("POST /logout", auth.Logout)

	mux.HandleFunc("/", handlers.Root)

	// Repo / run / finding handlers — Go 1.22+ pattern routing.
	repos := &handlers.RepoHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /repos", repos.List)
	mux.HandleFunc("GET /repos/{repo_id}", repos.Overview)
	mux.HandleFunc("GET /repos/{repo_id}/runs", repos.RunsList)
	mux.HandleFunc("GET /repos/{repo_id}/runs/{run_id}", repos.RunDetail)
	mux.HandleFunc("POST /repos/{repo_id}/runs/{run_id}/cancel", repos.RunCancel)
	mux.HandleFunc("GET /repos/{repo_id}/findings", repos.FindingsList)
	mux.HandleFunc("GET /repos/{repo_id}/findings/{finding_id}", repos.FindingDetail)

	// Live SSE timeline.
	sse := &handlers.RunsSSEHandler{Stores: cfg.Stores, Broadcaster: cfg.Broadcaster}
	mux.HandleFunc("GET /repos/{repo_id}/runs/{run_id}/events", sse.ServeSSE)

	// Transcript drawer.
	td := &handlers.TranscriptDrawerHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /repos/{repo_id}/runs/{run_id}/agents/{slot}/transcript", td.Serve)

	// Findings triage (modal openers + action endpoints).
	tr := &handlers.TriageHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /repos/{repo_id}/findings/{finding_id}/dismiss", tr.DismissModal)
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/dismiss", tr.Dismiss)
	mux.HandleFunc("GET /repos/{repo_id}/findings/{finding_id}/suppress", tr.SuppressModal)
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/suppress", tr.Suppress)
	mux.HandleFunc("GET /repos/{repo_id}/findings/{finding_id}/snooze", tr.SnoozeModal)
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/snooze", tr.Snooze)
	mux.HandleFunc("GET /repos/{repo_id}/findings/{finding_id}/note", tr.NoteModal)
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/notes", tr.AddNote)
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/reopen", tr.Reopen)
	mux.HandleFunc("POST /repos/{repo_id}/findings/bulk", tr.Bulk)

	// Per-repo settings.
	settings := &handlers.RepoSettingsHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /repos/{repo_id}/settings", settings.View)
	mux.HandleFunc("POST /repos/{repo_id}/settings", settings.Save)

	// Agent editor.
	agents := &handlers.AgentsHandler{
		Stores:       cfg.Stores,
		ToolRegistry: cfg.ToolRegistry,
		AppAuth:      cfg.AppAuth,
	}
	mux.HandleFunc("GET /agents", agents.List)
	mux.HandleFunc("GET /agents/new", agents.Editor)
	mux.HandleFunc("GET /agents/{name}", agents.Editor)
	mux.HandleFunc("POST /agents/{name}", agents.Save)
	mux.HandleFunc("GET /agents/{name}/commit", agents.CommitModal)
	mux.HandleFunc("POST /agents/{name}/commit", agents.Commit)
	mux.HandleFunc("GET /agents/{name}/import", agents.ImportModal)
	mux.HandleFunc("POST /agents/{name}/import", agents.Import)

	// Workflow editor.
	wf := &handlers.WorkflowsHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /workflows", wf.List)
	mux.HandleFunc("GET /workflows/{id}", wf.Editor)
	mux.HandleFunc("POST /workflows/{id}", wf.Save)
	mux.HandleFunc("POST /workflows/{id}/activate", wf.Activate)

	// Provider wizard.
	pv := &handlers.ProvidersHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /providers", pv.List)
	mux.HandleFunc("GET /providers/new", pv.Wizard)
	mux.HandleFunc("POST /providers", pv.Create)
	mux.HandleFunc("GET /providers/{id}", pv.Detail)
	mux.HandleFunc("POST /providers/{id}/test", pv.Test)
	mux.HandleFunc("POST /providers/{id}/models/refresh", pv.RefreshModels)

	// Org-level settings + users.
	sh := &handlers.SettingsHandler{Stores: cfg.Stores}
	mux.HandleFunc("GET /settings", sh.View)
	mux.HandleFunc("POST /settings", sh.Save)
	mux.HandleFunc("POST /settings/rotate-kek", sh.RotateKEK)
	mux.HandleFunc("GET /users", sh.UsersList)
	mux.HandleFunc("POST /users/{id}/role", sh.UpdateUserRole)

	// Compose middleware: outermost first.
	var handler http.Handler = mux
	handler = middleware.RequireAuth(handler)
	handler = middleware.CSRF(handler)
	handler = middleware.Session(cfg.Stores, cfg.SecureCookies)(handler)
	handler = secureHeaders(handler)
	handler = middleware.Logging(cfg.Log)(handler)
	handler = middleware.Recover(cfg.Log)(handler)
	handler = middleware.RequestID(handler)

	return &Server{
		cfg:     cfg,
		handler: handler,
		server: &http.Server{
			Addr:         cfg.Addr,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
	}
}

// Handler returns the composed root handler. Useful for httptest.
func (s *Server) Handler() http.Handler { return s.handler }

// Start blocks listening on the configured address.
func (s *Server) Start() error {
	s.cfg.Log.Info("web server starting", slog.String("addr", s.cfg.Addr))
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully drains connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// SSE responses set their own Content-Type; for HTML we let templ
		// inline styles. script-src 'self' covers the vendored htmx/alpine/
		// sortable bundles under /static/js/vendor/. We allow 'unsafe-eval'
		// because Alpine evaluates expressions at runtime; without it x-data
		// blocks silently. img-src allows GitHub avatars via https.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: https:; "+
				"script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; "+
				"connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
