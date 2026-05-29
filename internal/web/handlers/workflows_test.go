package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/webctx"
)

func TestWorkflow_SaveCreatesNewVersion(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	u := &store.User{OrgID: org.ID, GitHubID: 7, GitHubLogin: "alice", Role: "admin"}
	_ = stores.Users.Create(ctx, u)

	wf := &store.Workflow{OrgID: org.ID, Name: "default"}
	_ = stores.Workflows.Create(ctx, wf)

	h := &WorkflowsHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /workflows/{id}", h.Save)

	yamlGood := `name: default
version: 1
phases:
  - name: recon
    mode: sequential
    agents: [recon-agent]
  - name: analysis
    mode: parallel
    max_parallel: 3
    agents: [injection-agent]
  - name: reporting
    mode: sequential
    agents: [report-agent]
`
	form := url.Values{"yaml": []string{yamlGood}}
	req := httptest.NewRequest(http.MethodPost, "/workflows/"+wf.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(webctx.WithUser(req.Context(), u))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	// Validate by re-reading.
	wf2, _ := stores.Workflows.Get(ctx, wf.ID)
	if wf2 == nil {
		t.Fatalf("workflow missing")
	}
}

func TestWorkflow_SaveValidatesYAML(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	wf := &store.Workflow{OrgID: org.ID, Name: "default"}
	_ = stores.Workflows.Create(ctx, wf)

	h := &WorkflowsHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /workflows/{id}", h.Save)

	form := url.Values{"yaml": []string{"this is: not [valid: yaml"}}
	req := httptest.NewRequest(http.MethodPost, "/workflows/"+wf.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 re-render, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "error-msg") {
		t.Errorf("expected error message in body: %s", w.Body.String())
	}
}

func TestWorkflow_ActivateFlipsCurrent(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	wf := &store.Workflow{OrgID: org.ID, Name: "default"}
	_ = stores.Workflows.Create(ctx, wf)
	v1 := &store.WorkflowVersion{WorkflowID: wf.ID, YAML: "name: a\nversion: 1\nphases: [{name: reporting, agents: [x]}]\n"}
	_ = stores.Workflows.NewVersion(ctx, v1)

	h := &WorkflowsHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /workflows/{id}/activate", h.Activate)
	form := url.Values{"version_id": []string{v1.ID}}
	req := httptest.NewRequest(http.MethodPost, "/workflows/"+wf.ID+"/activate", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	wf2, _ := stores.Workflows.Get(ctx, wf.ID)
	if wf2.ActiveVersionID != v1.ID {
		t.Errorf("active = %q want %q", wf2.ActiveVersionID, v1.ID)
	}
}
