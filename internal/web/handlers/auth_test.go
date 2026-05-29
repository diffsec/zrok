package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/web/middleware"
)

func newAuthHandlerWithFake(t *testing.T, fake *fakeGitHub, orgLogin string, admin []string) (*AuthHandler, *fakeGitHub) {
	stores := newTestStores(t)
	cfg := AuthConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		OrgLogin:     orgLogin,
		AdminLogins:  admin,
		BaseURL:      "http://example.test",
		GitHub:       fake,
		Stores:       stores,
	}
	return NewAuthHandler(cfg), fake
}

func TestLoginStart_RedirectsWithState(t *testing.T) {
	fake := &fakeGitHub{}
	h, _ := newAuthHandlerWithFake(t, fake, "acme", nil)
	r := httptest.NewRequest(http.MethodGet, "/login/start", nil)
	w := httptest.NewRecorder()
	h.LoginStart(w, r)
	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize?") {
		t.Fatalf("bad redirect: %s", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") == "" {
		t.Fatal("missing state")
	}
	var sawStateCookie bool
	for _, c := range res.Cookies() {
		if c.Name == stateCookieName && c.Value != "" {
			sawStateCookie = true
		}
	}
	if !sawStateCookie {
		t.Fatal("expected state cookie")
	}
}

func TestCallback_OrgMismatch_Rejects(t *testing.T) {
	fake := &fakeGitHub{
		user:   &GitHubUser{ID: 1, Login: "bob", Name: "Bob"},
		emails: []GitHubEmail{{Email: "bob@example.com", Primary: true, Verified: true}},
		orgs:   []GitHubOrgMembership{{Login: "other-org"}},
	}
	h, _ := newAuthHandlerWithFake(t, fake, "acme", nil)
	r := newCallbackReq("code-abc", "state-xyz", "")
	w := httptest.NewRecorder()
	h.Callback(w, r)
	res := w.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}
	if !strings.Contains(w.Body.String(), "not a member of the configured organization") {
		t.Fatalf("expected org error message in body, got: %s", w.Body.String())
	}
}

func TestCallback_FirstUserBecomesAdmin(t *testing.T) {
	fake := &fakeGitHub{
		user:   &GitHubUser{ID: 7, Login: "alice", Name: "Alice"},
		emails: []GitHubEmail{{Email: "alice@example.com", Primary: true, Verified: true}},
		orgs:   []GitHubOrgMembership{{Login: "acme"}},
	}
	h, _ := newAuthHandlerWithFake(t, fake, "acme", nil)
	r := newCallbackReq("code", "state", "")
	w := httptest.NewRecorder()
	h.Callback(w, r)
	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d (body=%s)", res.StatusCode, w.Body.String())
	}
	if res.Header.Get("Location") != "/repos" {
		t.Fatalf("expected /repos redirect, got %s", res.Header.Get("Location"))
	}

	got, err := h.cfg.Stores.Users.GetByGitHubID(context.Background(), 7)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.Role != "admin" {
		t.Fatalf("first user should be admin, got %q", got.Role)
	}

	var sawSession, sawCSRF bool
	for _, c := range res.Cookies() {
		if c.Name == middleware.SessionCookieName && c.Value != "" {
			sawSession = true
		}
		if c.Name == middleware.CSRFCookieName && c.Value != "" {
			sawCSRF = true
		}
	}
	if !sawSession || !sawCSRF {
		t.Fatalf("session=%v csrf=%v", sawSession, sawCSRF)
	}

	tok, err := h.cfg.Stores.OAuth.Get(context.Background(), got.ID, "github")
	if err != nil {
		t.Fatalf("oauth get: %v", err)
	}
	if tok.AccessToken != "fake-access" {
		t.Fatalf("oauth token mismatch: %q", tok.AccessToken)
	}
}

func TestCallback_AdminListPromotion(t *testing.T) {
	fake := &fakeGitHub{
		user:   &GitHubUser{ID: 11, Login: "carol", Name: "Carol"},
		emails: []GitHubEmail{{Email: "carol@example.com", Primary: true, Verified: true}},
		orgs:   []GitHubOrgMembership{{Login: "acme"}},
	}
	h, _ := newAuthHandlerWithFake(t, fake, "acme", []string{"carol", "dave"})
	// Pre-seed a different user so carol is not first.
	ctx := context.Background()
	// Reuse the auth handler's ensureOrg to bootstrap the org.
	org, err := h.ensureOrg(ctx)
	if err != nil {
		t.Fatalf("ensure org: %v", err)
	}
	seed := newSeedUser(h, "preexisting")
	seed.OrgID = org.ID
	if err := h.cfg.Stores.Users.Create(ctx, seed); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := newCallbackReq("code", "state", "")
	w := httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (%s)", w.Code, w.Body.String())
	}
	got, err := h.cfg.Stores.Users.GetByGitHubID(ctx, 11)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.Role != "admin" {
		t.Fatalf("admin-list user should be admin, got %q", got.Role)
	}
}

func TestCallback_BadState_403(t *testing.T) {
	fake := &fakeGitHub{
		user:   &GitHubUser{ID: 1, Login: "alice"},
		emails: []GitHubEmail{{Email: "a@b", Primary: true, Verified: true}},
		orgs:   []GitHubOrgMembership{{Login: "acme"}},
	}
	h, _ := newAuthHandlerWithFake(t, fake, "acme", nil)
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=c&state=mismatch", nil)
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: "actual-state"})
	w := httptest.NewRecorder()
	h.Callback(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestLogout_DeletesSessionAndClearsCookies(t *testing.T) {
	fake := &fakeGitHub{}
	h, _ := newAuthHandlerWithFake(t, fake, "acme", nil)
	// Seed an org + user + session.
	ctx := context.Background()
	_, _ = h.ensureOrg(ctx)
	orgID, _ := h.cfg.Stores.Orgs.GetByGitHubLogin(ctx, "acme")
	u := newSeedUser(h, "bob")
	u.OrgID = orgID.ID
	if err := h.cfg.Stores.Users.Create(ctx, u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	sess := newTestSession(u.ID)
	if err := h.cfg.Stores.Sessions.Create(ctx, sess); err != nil {
		t.Fatalf("seed sess: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: sess.ID})
	// Inject session into ctx (mimics what Session middleware does).
	r = r.WithContext(stubSessionCtx(r.Context(), sess))
	w := httptest.NewRecorder()
	h.Logout(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	if _, err := h.cfg.Stores.Sessions.Get(ctx, sess.ID); err == nil {
		t.Fatal("session should have been deleted")
	}
}

// helpers ---------------------------------------------------------------

func newCallbackReq(code, state, cookieState string) *http.Request {
	if cookieState == "" {
		cookieState = state
	}
	r := httptest.NewRequest(http.MethodGet, "/oauth/callback?code="+code+"&state="+state, nil)
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: cookieState})
	return r
}
