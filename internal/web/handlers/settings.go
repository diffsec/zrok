// Package handlers — org-level settings + user management.
//
// GET /settings              org defaults + KEK rotation
// POST /settings             save org defaults
// POST /settings/rotate-kek  admin-only, behind maintenance=true flag
// GET /users                 list (admin)
// POST /users/{id}/role      promote/demote (admin)
package handlers

import (
	"net/http"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
	"github.com/diffsec/quokka/internal/web/webctx"
)

// SettingsHandler hosts the org-level pages.
type SettingsHandler struct {
	Stores *store.Stores
}

func (h *SettingsHandler) View(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	providers, _ := h.Stores.Providers.List(r.Context(), orgID)
	models := map[string][]*store.ProviderModel{}
	for _, p := range providers {
		ms, _ := h.Stores.ProviderModels.List(r.Context(), p.ID)
		models[p.ID] = ms
	}
	navRepos, _ := allReposForCtx(r, h.Stores)
	orgs, _ := h.Stores.Orgs.List(r.Context())
	orgName := ""
	if len(orgs) > 0 {
		orgName = orgs[0].Name
	}
	v := templates.SettingsView{
		Page:              pageData(r, "Settings", navRepos),
		Providers:         providers,
		AllProviderModels: models,
		OrgName:           orgName,
		Maintenance:       r.URL.Query().Get("maintenance") == "true",
	}
	renderHTML(w, r, templates.Settings(v))
}

func (h *SettingsHandler) Save(w http.ResponseWriter, r *http.Request) {
	// Org defaults are not modeled at the store-layer in PR-1A; persisting
	// them is a stub for PR-6. We return 303 to /settings to keep the form
	// flow consistent.
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// RotateKEK runs the same code path as `quokka admin rotate-keys`. Guarded
// by a maintenance=true URL flag so it isn't accidentally clicked.
func (h *SettingsHandler) RotateKEK(w http.ResponseWriter, r *http.Request) {
	u := webctx.UserFromCtx(r.Context())
	if u == nil || u.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Query().Get("maintenance") != "true" {
		http.Error(w, "maintenance flag required", http.StatusBadRequest)
		return
	}
	if h.Stores.Providers == nil {
		http.Error(w, "provider store unavailable", http.StatusInternalServerError)
		return
	}
	rotated, err := h.Stores.Providers.RotateKeys(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("rotated " + intToString(int(rotated)) + " rows\n"))
}

// UsersList renders /users.
func (h *SettingsHandler) UsersList(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	users, _ := h.Stores.Users.List(r.Context(), orgID)
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.UsersList(templates.UsersListView{
		Page:  pageData(r, "Users", navRepos),
		Users: users,
	}))
}

// UpdateUserRole handles POST /users/{id}/role.
func (h *SettingsHandler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	u := webctx.UserFromCtx(r.Context())
	if u == nil || u.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	role := r.PostForm.Get("role")
	if role != "admin" && role != "member" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	user, err := h.Stores.Users.Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	user.Role = role
	if err := h.Stores.Users.Update(r.Context(), user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// intToString avoids importing strconv in this file.
func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
