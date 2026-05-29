package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/middleware"
	"github.com/diffsec/quokka/internal/web/webctx"
)

func TestRepos_AnonymousRedirectsToLogin(t *testing.T) {
	stores := newTestStores(t)
	h := &RepoHandler{Stores: stores}

	mux := http.NewServeMux()
	mux.HandleFunc("/repos", h.List)
	handler := middleware.RequireAuth(mux)

	r := httptest.NewRequest(http.MethodGet, "/repos", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Fatalf("expected login redirect, got %s", loc)
	}
}

func TestRepos_AuthedRendersTable(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("org: %v", err)
	}
	u := &store.User{OrgID: org.ID, GitHubID: 1, GitHubLogin: "alice", Role: "admin"}
	if err := stores.Users.Create(ctx, u); err != nil {
		t.Fatalf("user: %v", err)
	}
	for i, fn := range []string{"acme/api", "acme/web"} {
		r := &store.Repository{
			OrgID:         org.ID,
			GitHubRepoID:  int64(1000 + i),
			FullName:      fn,
			DefaultBranch: "main",
			State:         "ready",
		}
		if err := stores.Repos.Create(ctx, r); err != nil {
			t.Fatalf("repo: %v", err)
		}
	}

	h := &RepoHandler{Stores: stores}
	r := httptest.NewRequest(http.MethodGet, "/repos", nil)
	r = r.WithContext(webctx.WithUser(r.Context(), u))
	r = r.WithContext(webctx.WithCSRFToken(r.Context(), "test-csrf"))
	w := httptest.NewRecorder()
	h.List(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"acme/api", "acme/web", "Repositories", "test-csrf"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q: %s", want, body)
		}
	}
}
