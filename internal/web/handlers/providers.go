// Package handlers — provider wizard.
//
// GET /providers              list
// GET /providers/new          wizard with preset shortcuts
// POST /providers             create (encrypts api_key via ProviderStore)
// GET /providers/{id}         detail (redacted key, test, refresh)
// POST /providers/{id}/test   harmless probe
// POST /providers/{id}/models/refresh   list models + write provider_models rows
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
)

// ProvidersHandler bundles provider CRUD + test + model discovery.
type ProvidersHandler struct {
	Stores *store.Stores
	// HTTPClient lets tests inject a fake. nil ⇒ http.DefaultClient with 15s timeout.
	HTTPClient *http.Client
}

func (h *ProvidersHandler) client() *http.Client {
	if h.HTTPClient != nil {
		return h.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

var providerPresets = []templates.ProviderPreset{
	{Key: "anthropic", Label: "Anthropic", Protocol: "anthropic", BaseURL: "https://api.anthropic.com"},
	{Key: "openai", Label: "OpenAI", Protocol: "openai-compatible", BaseURL: "https://api.openai.com/v1"},
	{Key: "openrouter", Label: "OpenRouter", Protocol: "openai-compatible", BaseURL: "https://openrouter.ai/api/v1"},
	{Key: "nanogpt", Label: "nanoGPT", Protocol: "openai-compatible", BaseURL: "https://nano-gpt.com/api/v1"},
	{Key: "ollama", Label: "Ollama", Protocol: "openai-compatible", BaseURL: "http://localhost:11434/v1"},
	{Key: "groq", Label: "Groq", Protocol: "openai-compatible", BaseURL: "https://api.groq.com/openai/v1"},
	{Key: "together", Label: "Together", Protocol: "openai-compatible", BaseURL: "https://api.together.xyz/v1"},
	{Key: "custom", Label: "Custom", Protocol: "openai-compatible", BaseURL: ""},
}

func (h *ProvidersHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	providers, _ := h.Stores.Providers.List(r.Context(), orgID)
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.ProvidersList(templates.ProvidersListView{
		Page:      pageData(r, "Providers", navRepos),
		Providers: providers,
	}))
}

func (h *ProvidersHandler) Wizard(w http.ResponseWriter, r *http.Request) {
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.ProviderWizard(templates.ProviderWizardView{
		Page:    pageData(r, "Add provider", navRepos),
		Presets: providerPresets,
	}))
}

func (h *ProvidersHandler) Create(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	protocol := r.PostForm.Get("protocol")
	baseURL := r.PostForm.Get("base_url")
	apiKey := r.PostForm.Get("api_key")
	preset := r.PostForm.Get("preset")
	if name == "" || protocol == "" || apiKey == "" {
		http.Error(w, "name, protocol, api_key required", http.StatusBadRequest)
		return
	}
	p := &store.Provider{
		OrgID:    orgID,
		Name:     name,
		Protocol: protocol,
		BaseURL:  baseURL,
		Preset:   preset,
		APIKey:   apiKey,
	}
	if err := h.Stores.Providers.Create(r.Context(), p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/providers/"+p.ID, http.StatusSeeOther)
}

func (h *ProvidersHandler) Detail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.Stores.Providers.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Redact the API key everywhere it's rendered.
	p.APIKey = redact(p.APIKey)
	models, _ := h.Stores.ProviderModels.List(r.Context(), p.ID)
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.ProviderDetail(templates.ProviderDetailView{
		Page:     pageData(r, p.Name, navRepos),
		Provider: p,
		Models:   models,
	}))
}

func (h *ProvidersHandler) Test(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.Stores.Providers.Get(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	msg, err := h.testConnection(r.Context(), p)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("error: " + err.Error()))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(msg))
}

// testConnection issues a harmless probe. anthropic: POST /v1/messages with
// max_tokens=1; openai-compat: GET /v1/models (returns the list) or, where
// /models is unavailable, a 1-token completion.
func (h *ProvidersHandler) testConnection(ctx context.Context, p *store.Provider) (string, error) {
	switch strings.ToLower(p.Protocol) {
	case "anthropic":
		body := []byte(`{"model":"claude-3-5-haiku-20241022","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}`)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/v1/messages", bytes.NewReader(body))
		req.Header.Set("x-api-key", p.APIKey)
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("Content-Type", "application/json")
		return doProbe(h.client(), req)
	case "openai-compatible", "openai":
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+"/models", nil)
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
		return doProbe(h.client(), req)
	default:
		return "", fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
}

func doProbe(c *http.Client, req *http.Request) (string, error) {
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return "ok (" + resp.Status + ")", nil
}

func (h *ProvidersHandler) RefreshModels(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.Stores.Providers.Get(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	models, err := h.discoverModels(r.Context(), p)
	if err != nil {
		http.Error(w, "discover: "+err.Error(), http.StatusBadGateway)
		return
	}
	// Replace the provider's models in-place.
	_ = h.Stores.ProviderModels.DeleteForProvider(r.Context(), p.ID)
	for _, m := range models {
		m.ProviderID = p.ID
		_ = h.Stores.ProviderModels.Upsert(r.Context(), m)
	}
	http.Redirect(w, r, "/providers/"+p.ID, http.StatusSeeOther)
}

// anthropicHardcodedModels — Anthropic doesn't expose /v1/models, so the
// wizard's "fetch models" button writes this static list.
var anthropicHardcodedModels = []*store.ProviderModel{
	{Model: "claude-opus-4-1-20250805", DisplayName: "Claude Opus 4.1", ContextWindow: 200000},
	{Model: "claude-sonnet-4-20250514", DisplayName: "Claude Sonnet 4", ContextWindow: 200000},
	{Model: "claude-3-5-haiku-20241022", DisplayName: "Claude Haiku 3.5", ContextWindow: 200000},
}

func (h *ProvidersHandler) discoverModels(ctx context.Context, p *store.Provider) ([]*store.ProviderModel, error) {
	switch strings.ToLower(p.Protocol) {
	case "anthropic":
		out := make([]*store.ProviderModel, len(anthropicHardcodedModels))
		for i, m := range anthropicHardcodedModels {
			cp := *m
			out[i] = &cp
		}
		return out, nil
	case "openai-compatible", "openai":
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.BaseURL+"/models", nil)
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
		resp, err := h.client().Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		var payload struct {
			Data []struct {
				ID     string `json:"id"`
				Object string `json:"object"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return nil, err
		}
		out := make([]*store.ProviderModel, 0, len(payload.Data))
		for _, m := range payload.Data {
			out = append(out, &store.ProviderModel{Model: m.ID, DisplayName: m.ID})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
}

func redact(key string) string {
	if len(key) <= 6 {
		return "***"
	}
	return key[:3] + "..." + key[len(key)-3:]
}
