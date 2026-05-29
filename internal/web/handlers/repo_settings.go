// Package handlers — per-repo settings page.
//
// GET /repos/{repo_id}/settings — renders the per-repo PR-feedback toggles
// (Check Run, Inline comments, Summary comment, severity threshold),
// workflow override picker, and a readonly view of index/onboarding state.
// POST persists the toggles via PRFeedbackStore.Upsert.
package handlers

import (
	"errors"
	"net/http"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
)

// RepoSettingsHandler is the per-repo settings GET/POST.
type RepoSettingsHandler struct {
	Stores *store.Stores
}

// View renders the settings form.
func (h *RepoSettingsHandler) View(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	settings, _ := h.Stores.PRFeedback.Get(r.Context(), repo.ID)
	if settings == nil {
		settings = &store.PRFeedbackSettings{
			RepoID:                repo.ID,
			CheckRunEnabled:       true,
			InlineCommentsEnabled: true,
			SummaryCommentEnabled: true,
		}
	}
	workflows, _ := h.Stores.Workflows.List(r.Context(), repo.OrgID)
	navRepos, _ := allReposForCtx(r, h.Stores)
	v := templates.RepoSettingsView{
		Page:      pageData(r, repo.FullName+" settings", navRepos),
		Repo:      repo,
		Settings:  settings,
		Workflows: workflows,
	}
	renderHTML(w, r, templates.RepoSettings(v))
}

// Save updates the per-repo PR-feedback settings.
func (h *RepoSettingsHandler) Save(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s := &store.PRFeedbackSettings{
		RepoID:                  repo.ID,
		CheckRunEnabled:         r.PostForm.Get("check_run") == "on",
		InlineCommentsEnabled:   r.PostForm.Get("inline_comments") == "on",
		SummaryCommentEnabled:   r.PostForm.Get("summary_comment") == "on",
		InlineSeverityThreshold: r.PostForm.Get("severity_threshold"),
	}
	if err := h.Stores.PRFeedback.Upsert(r.Context(), s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/repos/"+repo.ID+"/settings", http.StatusSeeOther)
}

// allReposForCtx is shared between admin pages that need the nav repo list
// without bouncing through the RepoHandler instance.
func allReposForCtx(r *http.Request, stores *store.Stores) ([]*store.Repository, error) {
	orgID, err := singleOrgID(r.Context(), stores)
	if err != nil {
		return nil, err
	}
	return stores.Repos.List(r.Context(), orgID)
}
