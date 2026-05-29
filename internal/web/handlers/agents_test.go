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

func TestAgent_SaveCreatesNewRevision(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	u := &store.User{OrgID: org.ID, GitHubID: 7, GitHubLogin: "alice", Role: "admin"}
	_ = stores.Users.Create(ctx, u)

	h := &AgentsHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agents/{name}", h.Save)

	form := url.Values{
		"description":     []string{"finds SQL injection"},
		"phase":           []string{"analysis"},
		"prompt_template": []string{"You are an injection-focused agent."},
		"tools_allowed":   []string{"navigate_read,finding_create"},
		"always_include":  []string{"on"},
		"project_types":   []string{"web-app"},
		"project_traits":  []string{"has-datastore"},
		"owns_cwes":       []string{"CWE-89,CWE-78"},
		"context_memories": []string{"sql-patterns"},
		"model_provider_id": []string{""},
		"model_name":      []string{""},
	}
	req := httptest.NewRequest(http.MethodPost, "/agents/injection-agent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(webctx.WithUser(req.Context(), u))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}

	ac, err := stores.AgentConfigs.GetByName(ctx, org.ID, "injection-agent")
	if err != nil {
		t.Fatalf("getbyname: %v", err)
	}
	revs, _ := stores.AgentConfigs.ListRevisions(ctx, ac.ID)
	if len(revs) != 1 {
		t.Fatalf("expected 1 revision, got %d", len(revs))
	}
	if revs[0].Revision != 1 {
		t.Errorf("revision = %d want 1", revs[0].Revision)
	}
	if !strings.Contains(revs[0].YAML, "injection-focused") {
		t.Errorf("yaml = %q", revs[0].YAML)
	}
	if ac.ActiveRevisionID != revs[0].ID {
		t.Errorf("active = %q want %q", ac.ActiveRevisionID, revs[0].ID)
	}
}

func TestAgent_EditorReadOnlyForHistoricalVersion(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	u := &store.User{OrgID: org.ID, GitHubID: 7, GitHubLogin: "alice", Role: "admin"}
	_ = stores.Users.Create(ctx, u)

	// Create two revisions.
	ac := &store.AgentConfigRow{OrgID: org.ID, Name: "x-agent", Phase: "analysis", Source: "ui"}
	_ = stores.AgentConfigs.Create(ctx, ac)
	rev1 := &store.AgentConfigRevision{AgentConfigID: ac.ID, YAML: "name: x-agent\nphase: analysis\nprompt_template: rev1\ntools_allowed: []\n"}
	_ = stores.AgentConfigs.NewRevision(ctx, rev1)
	rev2 := &store.AgentConfigRevision{AgentConfigID: ac.ID, YAML: "name: x-agent\nphase: analysis\nprompt_template: rev2\ntools_allowed: []\n"}
	_ = stores.AgentConfigs.NewRevision(ctx, rev2)
	_ = stores.AgentConfigs.SetActiveRevision(ctx, ac.ID, rev2.ID)

	h := &AgentsHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agents/{name}", h.Editor)
	req := httptest.NewRequest(http.MethodGet, "/agents/x-agent?version=1", nil)
	req = req.WithContext(webctx.WithUser(req.Context(), u))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "read-only") {
		t.Errorf("expected read-only marker, body: %s", body)
	}
	if !strings.Contains(body, "rev1") {
		t.Errorf("expected rev1 yaml, body: %s", body)
	}
}
