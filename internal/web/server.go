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
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		auth.Logout(w, r)
	})

	repos := &handlers.RepoHandler{Stores: cfg.Stores}
	mux.HandleFunc("/", handlers.Root)
	mux.HandleFunc("/repos", repos.List)
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/runs"):
			repos.RunsList(w, r)
		case strings.Contains(r.URL.Path, "/runs/"):
			repos.RunDetail(w, r)
		case strings.HasSuffix(r.URL.Path, "/findings"):
			repos.FindingsList(w, r)
		default:
			repos.Overview(w, r)
		}
	})

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
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: https:; "+
				"script-src 'self'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}
