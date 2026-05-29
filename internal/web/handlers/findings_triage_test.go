package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/middleware"
	"github.com/diffsec/quokka/internal/web/webctx"
)

func TestTriage_DismissPersistsAndLogsAction(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 1, FullName: "acme/x", DefaultBranch: "main", State: "ready"}
	_ = stores.Repos.Create(ctx, repo)
	f := &store.FindingRow{RepoID: repo.ID, Title: "issue", Severity: "high", File: "main.go", LineStart: 1, Status: "open", Fingerprint: "fp1", CreatedBy: "agent"}
	_ = stores.Findings.Create(ctx, f)
	u := &store.User{OrgID: org.ID, GitHubID: 7, GitHubLogin: "alice", Role: "admin"}
	_ = stores.Users.Create(ctx, u)

	h := &TriageHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/dismiss", h.Dismiss)

	form := url.Values{"reason": []string{"benign"}}
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/"+f.ID+"/dismiss", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(webctx.WithUser(req.Context(), u))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusNoContent {
		t.Fatalf("expected redirect, got %d: %s", w.Code, w.Body.String())
	}

	got, err := stores.Findings.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "false_positive" {
		t.Errorf("status = %q want false_positive", got.Status)
	}
	actions, _ := stores.FindingActions.List(ctx, f.ID)
	if len(actions) != 1 || actions[0].Action != "dismiss" {
		t.Errorf("expected 1 dismiss action, got %+v", actions)
	}
}

func TestTriage_SnoozeSetsStatus(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	repo, f := seedRepoFinding(t, stores, "open")
	h := &TriageHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/snooze", h.Snooze)

	form := url.Values{"until": []string{"2030-01-01"}, "reason": []string{"deferred"}}
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/"+f.ID+"/snooze", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusNoContent {
		t.Fatalf("status %d", w.Code)
	}
	got, _ := stores.Findings.Get(ctx, f.ID)
	if got.Status != "snoozed" {
		t.Errorf("status = %q", got.Status)
	}
}

func TestTriage_AddNote(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	repo, f := seedRepoFinding(t, stores, "open")
	h := &TriageHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/notes", h.AddNote)
	form := url.Values{"text": []string{"saw similar in CVE-2025-1234"}}
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/"+f.ID+"/notes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusNoContent {
		t.Fatalf("status %d", w.Code)
	}
	got, _ := stores.Findings.Get(ctx, f.ID)
	if !strings.Contains(got.NotesJSON, "CVE-2025-1234") {
		t.Errorf("notes = %s", got.NotesJSON)
	}
}

func TestTriage_ReopenBumpsCount(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	repo, f := seedRepoFinding(t, stores, "fixed")
	h := &TriageHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/reopen", h.Reopen)
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/"+f.ID+"/reopen", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther && w.Code != http.StatusNoContent {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	got, _ := stores.Findings.Get(ctx, f.ID)
	if got.Status != "open" {
		t.Errorf("status = %q", got.Status)
	}
	if got.ReopenedCount != 1 {
		t.Errorf("reopened_count = %d want 1", got.ReopenedCount)
	}
}

func TestTriage_BulkRunsInTransaction(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	repo := seedRepo(t, stores)
	var ids []string
	for i := 0; i < 5; i++ {
		f := &store.FindingRow{
			RepoID: repo.ID, Title: "low-" + strconv.Itoa(i),
			Severity: "low", File: "a.go", LineStart: 1, Status: "open",
			Fingerprint: "fp" + strconv.Itoa(i), CreatedBy: "agent",
		}
		if err := stores.Findings.Create(ctx, f); err != nil {
			t.Fatalf("create: %v", err)
		}
		ids = append(ids, f.ID)
	}
	h := &TriageHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/bulk", h.Bulk)
	form := url.Values{
		"action": []string{"dismiss"},
		"reason": []string{"batch"},
	}
	for _, id := range ids {
		form.Add("ids[]", id)
	}
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/bulk", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	for _, id := range ids {
		got, err := stores.Findings.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if got.Status != "false_positive" {
			t.Errorf("%s status = %q", id, got.Status)
		}
	}
}

func TestTriage_BulkCSRFProtected(t *testing.T) {
	stores := newTestStores(t)
	repo := seedRepo(t, stores)
	h := &TriageHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/bulk", h.Bulk)
	handler := middleware.CSRF(mux)

	// Missing CSRF cookie ⇒ 403.
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/bulk", strings.NewReader("action=dismiss&ids[]=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("missing cookie: expected 403, got %d", w.Code)
	}

	// csrf_token in form body matches cookie ⇒ middleware passes; handler
	// rejects bogus id with 500 (ok for this test).
	req = httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/bulk",
		strings.NewReader("action=dismiss&csrf_token=tok&ids[]=nope"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "q_csrf", Value: "tok"})
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Errorf("form csrf_token should satisfy middleware, got 403: %s", w.Body.String())
	}
}

func TestTriage_CSRFProtected(t *testing.T) {
	stores := newTestStores(t)
	repo, f := seedRepoFinding(t, stores, "open")
	h := &TriageHandler{Stores: stores}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/findings/{finding_id}/dismiss", h.Dismiss)
	handler := middleware.CSRF(mux)

	// CSRF: POST without cookie → 403.
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/"+f.ID+"/dismiss", strings.NewReader("reason=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	// With matching token in both cookie and header → 200.
	req = httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/findings/"+f.ID+"/dismiss", strings.NewReader("reason=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "q_csrf", Value: "tok"})
	req.Header.Set("X-CSRF-Token", "tok")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Errorf("unexpected 403 with token: %s", w.Body.String())
	}
}

// helpers
func seedRepo(t *testing.T, stores *store.Stores) *store.Repository {
	t.Helper()
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 1, FullName: "acme/x", DefaultBranch: "main", State: "ready"}
	_ = stores.Repos.Create(ctx, repo)
	return repo
}

func seedRepoFinding(t *testing.T, stores *store.Stores, status string) (*store.Repository, *store.FindingRow) {
	t.Helper()
	ctx := context.Background()
	repo := seedRepo(t, stores)
	f := &store.FindingRow{RepoID: repo.ID, Title: "t", Severity: "medium", File: "main.go", LineStart: 1, Status: status, Fingerprint: "fp", CreatedBy: "agent"}
	_ = stores.Findings.Create(ctx, f)
	return repo, f
}
