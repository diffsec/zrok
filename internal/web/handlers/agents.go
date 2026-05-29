// Package handlers — agent editor.
//
// GET /agents              list org-scoped agents
// GET /agents/{name}       editor form (or read-only for ?version=N)
// POST /agents/{name}      save → new revision
// GET/POST /agents/{name}/commit  open PR with YAML diff
// GET/POST /agents/{name}/import  seed from a connected repo's .quokka/agents/<name>.yaml
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop/tools"
	github0 "github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
	"github.com/diffsec/quokka/internal/web/webctx"
	gogithub "github.com/google/go-github/v66/github"
	"gopkg.in/yaml.v3"
)

// AgentsHandler bundles agent list + editor + import + commit-back PR.
type AgentsHandler struct {
	Stores       *store.Stores
	ToolRegistry *tools.Registry
	AppAuth      *github0.AppAuth
}

func (h *AgentsHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents, _ := h.Stores.AgentConfigs.List(r.Context(), orgID)
	navRepos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.AgentsList(templates.AgentsListView{
		Page:   pageData(r, "Agents", navRepos),
		Agents: agents,
	}))
}

func (h *AgentsHandler) Editor(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.PathValue("name")
	isNew := name == "" || strings.HasSuffix(r.URL.Path, "/agents/new")
	// ProjectTypes / ProjectTraits start empty and get populated from the
	// loaded config or registry entry; the template renders the selected
	// set first (each <option selected>) followed by the remaining
	// known-vocab entries via knownProjectTypesForUI / TraitsForUI.
	view := templates.AgentEditorView{
		Name:         name,
		IsNew:        isNew,
		Phase:        "analysis",
		AllToolNames: h.toolNames(),
	}
	providers, _ := h.Stores.Providers.List(r.Context(), orgID)
	view.Providers = providers
	if !isNew {
		ac, err := h.Stores.AgentConfigs.GetByName(r.Context(), orgID, name)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Allow editing built-in registry entries by name even when
				// no DB row exists yet — we fall through to a blank editor
				// pre-filled with the registry config.
				if built := agent.GetBuiltinAgent(name); built != nil {
					view.Description = built.Description
					view.Phase = string(built.Phase)
					view.PromptTemplate = built.PromptTemplate
					view.ToolsAllowed = built.ToolsAllowed
					view.ProjectTypes = append(view.ProjectTypes, built.Applicability.ProjectTypes...)
					view.AlwaysInclude = built.Applicability.AlwaysInclude
					view.ContextMemories = built.ContextMemories
				}
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			view.Description = ac.Description
			view.Phase = ac.Phase
			// Optional ?version=N renders the historical revision read-only.
			revisions, _ := h.Stores.AgentConfigs.ListRevisions(r.Context(), ac.ID)
			view.Revisions = revisions
			var selected *store.AgentConfigRevision
			if vstr := r.URL.Query().Get("version"); vstr != "" {
				n, _ := strconv.Atoi(vstr)
				for _, rev := range revisions {
					if rev.Revision == n {
						selected = rev
						view.ReadOnly = true
						break
					}
				}
			} else if ac.ActiveRevisionID != "" {
				for _, rev := range revisions {
					if rev.ID == ac.ActiveRevisionID {
						selected = rev
						break
					}
				}
			}
			if selected != nil {
				view.CurrentRevision = selected.Revision
				view.YAMLPreview = selected.YAML
				// Decode YAML into the editor's structured fields.
				if cfg, err := agent.LoadStrict([]byte(selected.YAML)); err == nil {
					view.PromptTemplate = cfg.PromptTemplate
					view.ToolsAllowed = cfg.ToolsAllowed
					view.ContextMemories = cfg.ContextMemories
					view.AlwaysInclude = cfg.Applicability.AlwaysInclude
					view.ProjectTypes = append(view.ProjectTypes, cfg.Applicability.ProjectTypes...)
					view.ProjectTraits = append(view.ProjectTraits, cfg.Applicability.ProjectTraits...)
					if cfg.ModelConfig != nil {
						view.ModelProviderID = cfg.ModelConfig.ProviderID
						view.ModelName = cfg.ModelConfig.Model
						view.Temperature = cfg.ModelConfig.Temperature
						view.MaxTokens = cfg.ModelConfig.MaxTokens
					}
				}
			}
		}
	}
	view.ConnectedRepos, _ = allReposForCtx(r, h.Stores)
	navRepos := view.ConnectedRepos
	view.Page = pageData(r, "Agent: "+name, navRepos)
	renderHTML(w, r, templates.AgentEditor(view))
}

func (h *AgentsHandler) Save(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg := agent.AgentConfig{
		Name:            name,
		Description:     r.PostForm.Get("description"),
		Phase:           agent.Phase(r.PostForm.Get("phase")),
		PromptTemplate:  r.PostForm.Get("prompt_template"),
		ToolsAllowed:    splitCSV(r.PostForm.Get("tools_allowed")),
		ContextMemories: splitCSV(r.PostForm.Get("context_memories")),
	}
	cfg.Applicability.AlwaysInclude = r.PostForm.Get("always_include") == "on"
	cfg.Applicability.ProjectTypes = r.PostForm["project_types"]
	cfg.Applicability.ProjectTraits = r.PostForm["project_traits"]
	cfg.Specialization.OwnsCWEs = splitCSV(r.PostForm.Get("owns_cwes"))
	mc := agent.ModelConfig{
		ProviderID: r.PostForm.Get("model_provider_id"),
		Model:      r.PostForm.Get("model_name"),
	}
	if t := r.PostForm.Get("temperature"); t != "" {
		if v, err := strconv.ParseFloat(t, 32); err == nil {
			mc.Temperature = float32(v)
		}
	}
	if t := r.PostForm.Get("max_tokens"); t != "" {
		if v, err := strconv.Atoi(t); err == nil {
			mc.MaxTokens = v
		}
	}
	if mc.ProviderID != "" || mc.Model != "" {
		cfg.ModelConfig = &mc
	}

	yml, err := yaml.Marshal(&cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Upsert the agent config row, then insert a new revision.
	ac, err := h.Stores.AgentConfigs.GetByName(r.Context(), orgID, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ac == nil {
		ac = &store.AgentConfigRow{
			OrgID:       orgID,
			Name:        name,
			Description: cfg.Description,
			Phase:       string(cfg.Phase),
			Source:      "ui",
		}
		if err := h.Stores.AgentConfigs.Create(r.Context(), ac); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		ac.Description = cfg.Description
		ac.Phase = string(cfg.Phase)
		if err := h.Stores.AgentConfigs.Create(r.Context(), ac); err != nil {
			// Create upserts on conflict, so reusing it is intentional.
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	var modelConfigJSON string
	if cfg.ModelConfig != nil {
		b, _ := json.Marshal(cfg.ModelConfig)
		modelConfigJSON = string(b)
	}
	rev := &store.AgentConfigRevision{
		AgentConfigID:   ac.ID,
		YAML:            string(yml),
		ModelConfigJSON: modelConfigJSON,
		CreatedBy:       actorID(r),
	}
	if err := h.Stores.AgentConfigs.NewRevision(r.Context(), rev); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.Stores.AgentConfigs.SetActiveRevision(r.Context(), ac.ID, rev.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/agents/"+name, http.StatusSeeOther)
}

func (h *AgentsHandler) CommitModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	repos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.AgentCommitModal(templates.CommitModalView{
		AgentName: name,
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
		Repos:     repos,
	}))
}

// Commit writes the agent's YAML to .quokka/agents/<name>.yaml on the target
// repo via the GitHub Contents API and opens a PR off a feature branch.
func (h *AgentsHandler) Commit(w http.ResponseWriter, r *http.Request) {
	if h.AppAuth == nil {
		http.Error(w, "commit-back disabled: GitHub App not configured", http.StatusServiceUnavailable)
		return
	}
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	repoID := r.PostForm.Get("repo_id")
	branch := r.PostForm.Get("branch")
	title := r.PostForm.Get("title")
	body := r.PostForm.Get("body")
	if repoID == "" || branch == "" {
		http.Error(w, "repo_id + branch required", http.StatusBadRequest)
		return
	}
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if repo.OrgID != orgID {
		http.NotFound(w, r)
		return
	}
	ac, err := h.Stores.AgentConfigs.GetByName(r.Context(), orgID, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	revisions, err := h.Stores.AgentConfigs.ListRevisions(r.Context(), ac.ID)
	if err != nil || len(revisions) == 0 {
		http.Error(w, "no revisions to commit", http.StatusBadRequest)
		return
	}
	yml := revisions[0].YAML

	install, err := h.Stores.Installations.Get(r.Context(), repo.InstallationID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prURL, err := openCommitPR(r.Context(), h.AppAuth, install.GitHubInstallationID, repo.FullName, repo.DefaultBranch, branch, name, yml, title, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, prURL, http.StatusSeeOther)
}

// openCommitPR is a thin helper that uses the GitHub App installation client
// to create a branch, put the YAML file, and open a PR. Each step is
// idempotent enough for re-attempts.
func openCommitPR(ctx context.Context, auth *github0.AppAuth, installID int64, fullName, baseBranch, headBranch, agentName, yml, title, body string) (string, error) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 {
		return "", errors.New("bad full name")
	}
	owner, repo := parts[0], parts[1]
	cli, err := auth.InstallationClient(ctx, installID)
	if err != nil {
		return "", err
	}
	// Get base ref SHA.
	base, _, err := cli.Git.GetRef(ctx, owner, repo, "heads/"+baseBranch)
	if err != nil {
		return "", fmt.Errorf("get base ref: %w", err)
	}
	headRef := "heads/" + headBranch
	if _, _, err := cli.Git.GetRef(ctx, owner, repo, headRef); err != nil {
		// Create the branch off base.
		newRef := &gogithub.Reference{
			Ref:    gptr("refs/" + headRef),
			Object: &gogithub.GitObject{SHA: base.Object.SHA},
		}
		if _, _, err := cli.Git.CreateRef(ctx, owner, repo, newRef); err != nil {
			return "", fmt.Errorf("create ref: %w", err)
		}
	}
	path := ".quokka/agents/" + agentName + ".yaml"
	// Check if the file already exists on the branch to capture the SHA.
	var existingSHA string
	if fc, _, _, err := cli.Repositories.GetContents(ctx, owner, repo, path, &gogithub.RepositoryContentGetOptions{Ref: headBranch}); err == nil && fc != nil && fc.SHA != nil {
		existingSHA = *fc.SHA
	}
	commitMsg := "Update agent " + agentName + " via quokka"
	opts := &gogithub.RepositoryContentFileOptions{
		Message: gptr(commitMsg),
		Content: []byte(yml),
		Branch:  gptr(headBranch),
	}
	if existingSHA != "" {
		opts.SHA = gptr(existingSHA)
	}
	if existingSHA != "" {
		if _, _, err := cli.Repositories.UpdateFile(ctx, owner, repo, path, opts); err != nil {
			return "", fmt.Errorf("update file: %w", err)
		}
	} else {
		if _, _, err := cli.Repositories.CreateFile(ctx, owner, repo, path, opts); err != nil {
			return "", fmt.Errorf("create file: %w", err)
		}
	}
	pr, _, err := cli.PullRequests.Create(ctx, owner, repo, &gogithub.NewPullRequest{
		Title: gptr(title),
		Body:  gptr(body),
		Head:  gptr(headBranch),
		Base:  gptr(baseBranch),
	})
	if err != nil {
		return "", fmt.Errorf("create pr: %w", err)
	}
	if pr.HTMLURL == nil {
		return "", errors.New("pr created, no html url")
	}
	return *pr.HTMLURL, nil
}

func gptr[T any](v T) *T { return &v }

func (h *AgentsHandler) ImportModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	repos, _ := allReposForCtx(r, h.Stores)
	renderHTML(w, r, templates.AgentImportModal(templates.CommitModalView{
		AgentName: name,
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
		Repos:     repos,
	}))
}

// Import reads .quokka/agents/<name>.yaml from the selected repo via Contents
// API and returns the editor form pre-filled.
func (h *AgentsHandler) Import(w http.ResponseWriter, r *http.Request) {
	if h.AppAuth == nil {
		http.Error(w, "import disabled: GitHub App not configured", http.StatusServiceUnavailable)
		return
	}
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	repoID := r.PostForm.Get("repo_id")
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil || repo.OrgID != orgID {
		http.NotFound(w, r)
		return
	}
	install, err := h.Stores.Installations.Get(r.Context(), repo.InstallationID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cli, err := h.AppAuth.InstallationClient(r.Context(), install.GitHubInstallationID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "bad full name", http.StatusInternalServerError)
		return
	}
	fc, _, _, err := cli.Repositories.GetContents(r.Context(), parts[0], parts[1], ".quokka/agents/"+name+".yaml", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	content, err := fc.GetContent()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	cfg, err := agent.LoadStrict([]byte(content))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Save imported config as a new revision.
	ac, _ := h.Stores.AgentConfigs.GetByName(r.Context(), orgID, name)
	if ac == nil {
		ac = &store.AgentConfigRow{
			OrgID:       orgID,
			Name:        name,
			Description: cfg.Description,
			Phase:       string(cfg.Phase),
			Source:      "repo-import",
		}
		_ = h.Stores.AgentConfigs.Create(r.Context(), ac)
	}
	rev := &store.AgentConfigRevision{
		AgentConfigID: ac.ID,
		YAML:          content,
		CreatedBy:     actorID(r),
	}
	if err := h.Stores.AgentConfigs.NewRevision(r.Context(), rev); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = h.Stores.AgentConfigs.SetActiveRevision(r.Context(), ac.ID, rev.ID)
	http.Redirect(w, r, "/agents/"+name, http.StatusSeeOther)
}

func (h *AgentsHandler) toolNames() []string {
	if h.ToolRegistry == nil {
		return nil
	}
	return h.ToolRegistry.AllToolNames()
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

