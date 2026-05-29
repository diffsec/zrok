package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestProviders_CreateEncryptsAPIKey(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)

	h := &ProvidersHandler{Stores: stores}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /providers", h.Create)
	form := url.Values{
		"name":     []string{"Anthropic"},
		"protocol": []string{"anthropic"},
		"base_url": []string{"https://api.anthropic.com"},
		"preset":   []string{"anthropic"},
		"api_key":  []string{"sk-ant-test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/providers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	providers, err := stores.Providers.List(ctx, org.ID)
	if err != nil || len(providers) != 1 {
		t.Fatalf("list: %v %d", err, len(providers))
	}
	// Get should decrypt back to plaintext.
	p, _ := stores.Providers.Get(ctx, providers[0].ID)
	if p.APIKey != "sk-ant-test-secret" {
		t.Errorf("api_key after Get = %q want plaintext", p.APIKey)
	}
	// Confirm the underlying DB column is not the plaintext.
	var raw string
	row := stores.DB.QueryRow(`SELECT COALESCE(api_key_enc,'') FROM providers WHERE id=?`, p.ID)
	_ = row.Scan(&raw)
	if strings.Contains(raw, "sk-ant-test-secret") {
		t.Errorf("ciphertext column contains plaintext: %q", raw)
	}
}

func TestProviders_TestConnectionMockOK(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)

	// Spin up a stand-in upstream that returns 200 from /v1/models.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/models" {
			w.Write([]byte(`{"data":[{"id":"gpt-x","object":"model"}]}`))
			return
		}
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer upstream.Close()

	p := &store.Provider{
		OrgID: org.ID, Name: "openai-test", Protocol: "openai-compatible",
		BaseURL: upstream.URL, APIKey: "sk-test",
	}
	_ = stores.Providers.Create(ctx, p)
	h := &ProvidersHandler{Stores: stores, HTTPClient: upstream.Client()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /providers/{id}/test", h.Test)

	req := httptest.NewRequest(http.MethodPost, "/providers/"+p.ID+"/test", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(w.Body.String(), "ok") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestProviders_RefreshModelsWritesRows(t *testing.T) {
	stores := newTestStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /models returns an openai-compatible list.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]string{
				{"id": "gpt-x", "object": "model"},
				{"id": "gpt-y", "object": "model"},
			},
		})
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer upstream.Close()

	p := &store.Provider{
		OrgID: org.ID, Name: "openai-test", Protocol: "openai-compatible",
		BaseURL: upstream.URL, APIKey: "sk-test",
	}
	_ = stores.Providers.Create(ctx, p)
	h := &ProvidersHandler{Stores: stores, HTTPClient: upstream.Client()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /providers/{id}/models/refresh", h.RefreshModels)

	req := httptest.NewRequest(http.MethodPost, "/providers/"+p.ID+"/models/refresh", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	models, _ := stores.ProviderModels.List(ctx, p.ID)
	if len(models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(models))
	}
}
