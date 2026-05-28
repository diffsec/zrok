package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/webctx"
	"github.com/diffsec/quokka/internal/web/templates"
)

// RepoHandler bundles dependencies for repo-related routes.
type RepoHandler struct {
	Stores *store.Stores
}

// List renders /repos.
func (h *RepoHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := singleOrgID(r.Context(), h.Stores)
	if err != nil {
		http.Error(w, "no organization configured", http.StatusInternalServerError)
		return
	}
	repos, err := h.Stores.Repos.List(r.Context(), orgID)
	if err != nil {
		http.Error(w, "list repos: "+err.Error(), http.StatusInternalServerError)
		return
	}
	v := templates.ReposView{
		Page:  pageData(r, "Repositories", repos),
		Repos: repos,
	}
	renderHTML(w, r, templates.Repos(v))
}

// Overview renders /repos/{repo_id}.
func (h *RepoHandler) Overview(w http.ResponseWriter, r *http.Request) {
	repoID := pathParam(r.URL.Path, "/repos/")
	if repoID == "" {
		http.Error(w, "missing repo id", http.StatusBadRequest)
		return
	}
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	runs, err := h.Stores.Runs.List(r.Context(), repo.ID, 10, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	findings, err := h.Stores.Findings.List(r.Context(), repo.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bySev := map[string]int{}
	for _, f := range findings {
		if f.Status == "open" || f.Status == "" {
			bySev[f.Severity]++
		}
	}
	navRepos, _ := h.allRepos(r.Context())
	v := templates.RepoOverviewView{
		Page:              pageData(r, repo.FullName, navRepos),
		Repo:              repo,
		RecentRuns:        runs,
		OpenFindingsBySev: bySev,
	}
	renderHTML(w, r, templates.RepoOverview(v))
}

// RunsList renders /repos/{repo_id}/runs.
func (h *RepoHandler) RunsList(w http.ResponseWriter, r *http.Request) {
	repoID := pathParam(r.URL.Path, "/repos/")
	if i := strings.Index(repoID, "/"); i >= 0 {
		repoID = repoID[:i]
	}
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	limit := 25
	offset := atoiSafe(r.URL.Query().Get("offset"))
	runs, err := h.Stores.Runs.List(r.Context(), repo.ID, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	navRepos, _ := h.allRepos(r.Context())
	v := templates.RunsListView{
		Page:   pageData(r, repo.FullName+" runs", navRepos),
		Repo:   repo,
		Runs:   runs,
		Limit:  limit,
		Offset: offset,
		Total:  len(runs),
	}
	renderHTML(w, r, templates.RunsList(v))
}

// RunDetail renders /repos/{repo_id}/runs/{run_id}.
func (h *RepoHandler) RunDetail(w http.ResponseWriter, r *http.Request) {
	repoID, runID := splitRunPath(r.URL.Path)
	if repoID == "" || runID == "" {
		http.NotFound(w, r)
		return
	}
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	run, err := h.Stores.Runs.Get(r.Context(), runID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if run.RepoID != repo.ID {
		http.NotFound(w, r)
		return
	}
	// FindingStore.List currently lists by repo only; PR-5 adds a run filter.
	findings, _ := h.Stores.Findings.List(r.Context(), repo.ID)
	var runFindings []*store.FindingRow
	for _, f := range findings {
		if f.RunID == run.ID {
			runFindings = append(runFindings, f)
		}
	}
	navRepos, _ := h.allRepos(r.Context())
	v := templates.RunView{
		Page:     pageData(r, "Run", navRepos),
		Repo:     repo,
		Run:      run,
		Findings: runFindings,
	}
	renderHTML(w, r, templates.RunPage(v))
}

// FindingsList renders /repos/{repo_id}/findings.
func (h *RepoHandler) FindingsList(w http.ResponseWriter, r *http.Request) {
	repoID := pathParam(r.URL.Path, "/repos/")
	if i := strings.Index(repoID, "/"); i >= 0 {
		repoID = repoID[:i]
	}
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	all, err := h.Stores.Findings.List(r.Context(), repo.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	filt := templates.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		Path:     r.URL.Query().Get("path"),
		CWE:      r.URL.Query().Get("cwe"),
		Agent:    r.URL.Query().Get("agent"),
	}
	filtered := filterFindings(all, filt)
	navRepos, _ := h.allRepos(r.Context())
	v := templates.FindingsListView{
		Page:     pageData(r, repo.FullName+" findings", navRepos),
		Repo:     repo,
		Findings: filtered,
		Filter:   filt,
	}
	renderHTML(w, r, templates.FindingsList(v))
}

// Root renders / — redirects to /repos when authed, /login when not.
func Root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if webctx.UserFromCtx(r.Context()) != nil {
		http.Redirect(w, r, "/repos", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *RepoHandler) allRepos(ctx context.Context) ([]*store.Repository, error) {
	orgID, err := singleOrgID(ctx, h.Stores)
	if err != nil {
		return nil, err
	}
	return h.Stores.Repos.List(ctx, orgID)
}

func filterFindings(in []*store.FindingRow, f templates.FindingFilter) []*store.FindingRow {
	var out []*store.FindingRow
	for _, r := range in {
		if f.Severity != "" && r.Severity != f.Severity {
			continue
		}
		if f.Status != "" && r.Status != f.Status {
			continue
		}
		if f.CWE != "" && r.CWE != f.CWE {
			continue
		}
		if f.Path != "" && !strings.Contains(r.File, f.Path) {
			continue
		}
		out = append(out, r)
	}
	return out
}
