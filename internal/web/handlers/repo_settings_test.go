package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestRepoSettings_TogglesPersist(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 1, FullName: "acme/x", DefaultBranch: "main", State: "ready"}
	_ = stores.Repos.Create(ctx, repo)

	h := &RepoSettingsHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{repo_id}/settings", h.Save)

	form := url.Values{
		"check_run":          []string{"on"},
		"inline_comments":    []string{"on"},
		// summary_comment intentionally omitted → false
		"severity_threshold": []string{"high"},
	}
	req := httptest.NewRequest(http.MethodPost, "/repos/"+repo.ID+"/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	got, err := stores.PRFeedback.Get(ctx, repo.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.CheckRunEnabled || !got.InlineCommentsEnabled || got.SummaryCommentEnabled {
		t.Errorf("toggles = %+v", got)
	}
	if got.InlineSeverityThreshold != "high" {
		t.Errorf("threshold = %q", got.InlineSeverityThreshold)
	}
}
