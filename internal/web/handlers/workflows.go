// Package handlers — workflow editor.
//
// GET /workflows
// GET /workflows/{id}             phase editor
// POST /workflows/{id}            validate + new version
// POST /workflows/{id}/activate
package handlers

import (
	"errors"
	"net/http"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
	"github.com/diffsec/quokka/internal/workflow"
)

// WorkflowsHandler bundles workflow list + editor + activate.
type WorkflowsHandler struct {
	Stores *store.Stores
}

func (h *WorkflowsHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	workflows, _ := h.Stores.Workflows.List(r.Context(), orgID)
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.WorkflowsList(templates.WorkflowsListView{
		Page:      pageData(r, "Workflows", navRepos),
		Workflows: workflows,
	}))
}

func (h *WorkflowsHandler) Editor(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	wf, err := h.Stores.Workflows.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if wf.OrgID != orgID {
		http.NotFound(w, r)
		return
	}
	var ver *store.WorkflowVersion
	if wf.ActiveVersionID != "" {
		ver, _ = h.Stores.Workflows.GetVersion(r.Context(), wf.ActiveVersionID)
	}
	yamlStr := ""
	if ver != nil {
		yamlStr = ver.YAML
	}
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.WorkflowEditor(templates.WorkflowEditorView{
		Page:     pageData(r, wf.Name, navRepos),
		Workflow: wf,
		Version:  ver,
		YAML:     yamlStr,
	}))
}

func (h *WorkflowsHandler) Save(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	wf, err := h.Stores.Workflows.Get(r.Context(), id)
	if err != nil || wf.OrgID != orgID {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	yamlStr := r.PostForm.Get("yaml")
	if _, err := workflow.Parse([]byte(yamlStr)); err != nil {
		// Re-render the editor with the error.
		navRepos, _ := allReposForCtx(r, h.Stores)
		renderHTML(w, r, templates.WorkflowEditor(templates.WorkflowEditorView{
			Page:     pageData(r, wf.Name, navRepos),
			Workflow: wf,
			YAML:     yamlStr,
			Error:    err.Error(),
		}))
		return
	}
	ver := &store.WorkflowVersion{
		WorkflowID: wf.ID,
		YAML:       yamlStr,
		CreatedBy:  actorID(r),
	}
	if err := h.Stores.Workflows.NewVersion(r.Context(), ver); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/workflows/"+wf.ID, http.StatusSeeOther)
}

func (h *WorkflowsHandler) Activate(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	wf, err := h.Stores.Workflows.Get(r.Context(), id)
	if err != nil || wf.OrgID != orgID {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	versionID := r.PostForm.Get("version_id")
	if versionID == "" {
		http.Error(w, "version_id required", http.StatusBadRequest)
		return
	}
	if err := h.Stores.Workflows.SetActiveVersion(r.Context(), wf.ID, versionID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/workflows/"+wf.ID, http.StatusSeeOther)
}
