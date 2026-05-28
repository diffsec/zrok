package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/middleware"
	"github.com/diffsec/quokka/internal/web/webctx"
	"github.com/diffsec/quokka/internal/web/templates"
)

// AuthConfig collects every knob the OAuth handler needs at construction time.
// All values come from env vars at server.go boot.
type AuthConfig struct {
	ClientID       string
	ClientSecret   string
	OrgLogin       string   // required GitHub org membership; empty means deny all
	AdminLogins    []string // promote-on-create allowlist
	BaseURL        string   // e.g. http://localhost:8080
	SecureCookies  bool
	GitHub         GitHubClient
	Stores         *store.Stores
	Log            *slog.Logger
	Now            func() time.Time
	StateCookieTTL time.Duration
}

const (
	stateCookieName    = "q_oauth_state"
	stateCookieDefault = 10 * time.Minute
	oauthAuthorizeURL  = "https://github.com/login/oauth/authorize"
)

// AuthHandler wraps AuthConfig so each method has access to dependencies.
type AuthHandler struct {
	cfg AuthConfig
}

// NewAuthHandler validates the config and returns a handler bundle.
func NewAuthHandler(cfg AuthConfig) *AuthHandler {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.StateCookieTTL == 0 {
		cfg.StateCookieTTL = stateCookieDefault
	}
	return &AuthHandler{cfg: cfg}
}

// LoginPage renders the templ login page. If the user is already authed it
// just redirects to /repos.
func (h *AuthHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	if webctx.UserFromCtx(r.Context()) != nil {
		http.Redirect(w, r, "/repos", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := r.URL.Query().Get("error")
	next := r.URL.Query().Get("next")
	if err2 := templates.Login(err, next, webctx.CSRFTokenFromCtx(r.Context())).Render(r.Context(), w); err2 != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// LoginStart kicks off the OAuth handshake by minting a state value and
// 302-ing the browser to GitHub.
func (h *AuthHandler) LoginStart(w http.ResponseWriter, r *http.Request) {
	if h.cfg.ClientID == "" {
		http.Error(w, "oauth not configured: QUOKKA_GITHUB_APP_CLIENT_ID missing", http.StatusInternalServerError)
		return
	}
	state := newState()
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/oauth/callback",
		MaxAge:   int(h.cfg.StateCookieTTL / time.Second),
		HttpOnly: true,
		Secure:   h.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	next := r.URL.Query().Get("next")
	q := url.Values{
		"client_id":    {h.cfg.ClientID},
		"redirect_uri": {strings.TrimRight(h.cfg.BaseURL, "/") + "/oauth/callback"},
		"scope":        {"read:user read:org user:email"},
		"state":        {encodeState(state, next)},
	}
	http.Redirect(w, r, oauthAuthorizeURL+"?"+q.Encode(), http.StatusFound)
}

// Callback handles the GitHub redirect, exchanges code, fetches identity,
// enforces the org gate, upserts user + session + oauth token, and lands the
// browser on /repos.
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	rawState := r.URL.Query().Get("state")
	if code == "" || rawState == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	state, next := decodeState(rawState)
	c, err := r.Cookie(stateCookieName)
	if err != nil || c.Value == "" || c.Value != state {
		http.Error(w, "invalid state", http.StatusForbidden)
		return
	}
	// State is single-use; clear it.
	http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Value: "", Path: "/oauth/callback",
		MaxAge: -1, HttpOnly: true, Secure: h.cfg.SecureCookies, SameSite: http.SameSiteLaxMode,
	})

	if h.cfg.GitHub == nil {
		http.Error(w, "github client not configured", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()
	tok, err := h.cfg.GitHub.ExchangeCode(ctx, code)
	if err != nil {
		h.cfg.Log.Warn("oauth exchange failed", slog.Any("err", err))
		http.Error(w, "oauth exchange failed", http.StatusBadGateway)
		return
	}
	ghUser, err := h.cfg.GitHub.GetUser(ctx, tok.AccessToken)
	if err != nil {
		h.cfg.Log.Warn("get user failed", slog.Any("err", err))
		http.Error(w, "get user failed", http.StatusBadGateway)
		return
	}
	emails, _ := h.cfg.GitHub.GetUserEmails(ctx, tok.AccessToken)
	orgs, err := h.cfg.GitHub.GetUserOrgs(ctx, tok.AccessToken)
	if err != nil {
		h.cfg.Log.Warn("get orgs failed", slog.Any("err", err))
		http.Error(w, "get orgs failed", http.StatusBadGateway)
		return
	}
	if !orgMatches(h.cfg.OrgLogin, orgs) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = templates.Login("not_in_org", "", webctx.CSRFTokenFromCtx(r.Context())).Render(r.Context(), w)
		return
	}

	org, err := h.ensureOrg(ctx)
	if err != nil {
		h.cfg.Log.Error("ensure org", slog.Any("err", err))
		http.Error(w, "org bootstrap failed", http.StatusInternalServerError)
		return
	}

	primaryEmail := ghUser.Email
	if primaryEmail == "" {
		for _, e := range emails {
			if e.Primary && e.Verified {
				primaryEmail = e.Email
				break
			}
		}
	}

	user, err := h.upsertUser(ctx, org.ID, ghUser, primaryEmail)
	if err != nil {
		h.cfg.Log.Error("upsert user", slog.Any("err", err))
		http.Error(w, "user upsert failed", http.StatusInternalServerError)
		return
	}

	// Encrypted OAuth token store.
	if err := h.cfg.Stores.OAuth.Upsert(ctx, &store.OAuthToken{
		UserID:      user.ID,
		Provider:    "github",
		AccessToken: tok.AccessToken,
		Scopes:      tok.Scope,
	}); err != nil {
		h.cfg.Log.Error("oauth upsert", slog.Any("err", err))
		http.Error(w, "oauth persist failed", http.StatusInternalServerError)
		return
	}

	now := h.cfg.Now()
	sess := &store.Session{
		UserID:    user.ID,
		ExpiresAt: now.Add(middleware.SessionTTL),
		IP:        clientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
	}
	if err := h.cfg.Stores.Sessions.Create(ctx, sess); err != nil {
		h.cfg.Log.Error("session create", slog.Any("err", err))
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}
	middleware.WriteSessionCookie(w, sess.ID, h.cfg.SecureCookies)
	middleware.WriteCSRFCookie(w, middleware.NewCSRFToken(), h.cfg.SecureCookies)

	dest := "/repos"
	if next != "" && strings.HasPrefix(next, "/") {
		dest = next
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// Logout deletes the session row and clears both cookies.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := webctx.SessionFromCtx(r.Context())
	if sess != nil {
		_ = h.cfg.Stores.Sessions.Delete(r.Context(), sess.ID)
	}
	middleware.ClearCookies(w, h.cfg.SecureCookies)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ensureOrg returns the singleton organizations row, creating it if absent.
// One row per instance — see the plan's "single org per instance" decision.
func (h *AuthHandler) ensureOrg(ctx context.Context) (*store.Org, error) {
	if h.cfg.OrgLogin != "" {
		o, err := h.cfg.Stores.Orgs.GetByGitHubLogin(ctx, h.cfg.OrgLogin)
		if err == nil {
			return o, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}
	all, err := h.cfg.Stores.Orgs.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(all) > 0 {
		return all[0], nil
	}
	o := &store.Org{Name: h.cfg.OrgLogin, GitHubLogin: h.cfg.OrgLogin}
	if o.Name == "" {
		o.Name = "default"
	}
	if err := h.cfg.Stores.Orgs.Create(ctx, o); err != nil {
		return nil, err
	}
	return o, nil
}

// upsertUser creates or updates the users row for this GitHub identity and
// applies first-user-or-allowlist admin promotion.
func (h *AuthHandler) upsertUser(ctx context.Context, orgID string, gh *GitHubUser, email string) (*store.User, error) {
	existing, err := h.cfg.Stores.Users.GetByGitHubID(ctx, gh.ID)
	now := h.cfg.Now()
	if err == nil {
		existing.Email = email
		existing.Name = gh.Name
		existing.AvatarURL = gh.AvatarURL
		existing.LastLoginAt = &now
		if err := h.cfg.Stores.Users.Update(ctx, existing); err != nil {
			return nil, err
		}
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	role := "member"
	all, err := h.cfg.Stores.Users.List(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		role = "admin"
	} else if h.isAdminListed(gh.Login) {
		role = "admin"
	}

	u := &store.User{
		OrgID:       orgID,
		GitHubID:    gh.ID,
		GitHubLogin: gh.Login,
		Email:       email,
		Name:        gh.Name,
		AvatarURL:   gh.AvatarURL,
		Role:        role,
		LastLoginAt: &now,
	}
	if err := h.cfg.Stores.Users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (h *AuthHandler) isAdminListed(login string) bool {
	low := strings.ToLower(login)
	for _, a := range h.cfg.AdminLogins {
		if strings.EqualFold(strings.TrimSpace(a), low) {
			return true
		}
	}
	return false
}

func orgMatches(want string, memberships []GitHubOrgMembership) bool {
	if want == "" {
		// Without an explicit gate, deny all logins. Brief calls this out as a
		// judgment call; v1 errs on the safe side.
		return false
	}
	for _, m := range memberships {
		if strings.EqualFold(m.Login, want) {
			return true
		}
	}
	return false
}

// encodeState bundles a random state token with the optional `next` URL so we
// can pass through a return path without an extra cookie.
func encodeState(state, next string) string {
	if next == "" {
		return state
	}
	return state + ":" + url.QueryEscape(next)
}

// decodeState splits encodeState's output back into (state, next).
func decodeState(raw string) (string, string) {
	idx := strings.IndexByte(raw, ':')
	if idx < 0 {
		return raw, ""
	}
	next, _ := url.QueryUnescape(raw[idx+1:])
	return raw[:idx], next
}

func newState() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if idx := strings.IndexByte(v, ','); idx >= 0 {
			return strings.TrimSpace(v[:idx])
		}
		return strings.TrimSpace(v)
	}
	return r.RemoteAddr
}
