package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
	"github.com/diffsec/quokka/internal/web/webctx"
)

// jsonPkgUnmarshal is a thin alias so we can swap encoding/json later.
var jsonPkgUnmarshal = json.Unmarshal

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
	repoID := r.PathValue("repo_id")
	if repoID == "" {
		repoID = pathParam(r.URL.Path, "/repos/")
	}
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
	repoID := r.PathValue("repo_id")
	if repoID == "" {
		repoID = pathParam(r.URL.Path, "/repos/")
		if i := strings.Index(repoID, "/"); i >= 0 {
			repoID = repoID[:i]
		}
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
	repoID := r.PathValue("repo_id")
	runID := r.PathValue("run_id")
	if repoID == "" || runID == "" {
		repoID, runID = splitRunPath(r.URL.Path)
	}
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
	// Derive phase cards from the timeline_events the worker has emitted so far.
	events, _ := h.Stores.Events.Stream(r.Context(), run.ID, time.Time{})
	phases := buildPhaseCards(events)
	v := templates.RunView{
		Page:     pageData(r, "Run", navRepos),
		Repo:     repo,
		Run:      run,
		Findings: runFindings,
		Phases:   phases,
	}
	renderHTML(w, r, templates.RunPage(v))
}

// buildPhaseCards collapses timeline_events into phase + agent cards. We rely
// on the well-known event types emitted by internal/worker/jobs/run_pr.go.
func buildPhaseCards(events []*store.TimelineEvent) []templates.RunPhaseCard {
	if len(events) == 0 {
		return nil
	}
	phaseByName := map[string]*templates.RunPhaseCard{}
	order := []string{}
	agentSlot := map[string]*templates.RunAgentCard{}
	currentPhase := ""
	for _, ev := range events {
		switch ev.EventType {
		case "phase_start":
			name := jsonField(ev.PayloadJSON, "state")
			if name == "" {
				name = "phase"
			}
			currentPhase = name
			if _, ok := phaseByName[name]; !ok {
				phaseByName[name] = &templates.RunPhaseCard{Name: name, Status: "running"}
				order = append(order, name)
			}
		case "phase_end":
			name := jsonField(ev.PayloadJSON, "state")
			if p, ok := phaseByName[name]; ok {
				p.Status = "completed"
			}
		case "agent_start":
			agent := jsonField(ev.PayloadJSON, "agent")
			if agent == "" {
				continue
			}
			if currentPhase == "" {
				currentPhase = "running"
				if _, ok := phaseByName[currentPhase]; !ok {
					phaseByName[currentPhase] = &templates.RunPhaseCard{Name: currentPhase, Status: "running"}
					order = append(order, currentPhase)
				}
			}
			card := &templates.RunAgentCard{Slot: agent, Name: agent, Status: "running"}
			agentSlot[agent] = card
			phaseByName[currentPhase].Agents = append(phaseByName[currentPhase].Agents, *card)
		case "agent_end":
			agent := jsonField(ev.PayloadJSON, "agent")
			if a, ok := agentSlot[agent]; ok {
				a.Status = "completed"
			}
			// also update in-place in the phase agents slice
			for pn := range phaseByName {
				for i, ag := range phaseByName[pn].Agents {
					if ag.Name == agent {
						phaseByName[pn].Agents[i].Status = "completed"
					}
				}
			}
		case "run_failed":
			for _, p := range phaseByName {
				if p.Status == "running" {
					p.Status = "failed"
				}
			}
		case "run_completed", "run_cancelled":
			for _, p := range phaseByName {
				if p.Status == "running" {
					p.Status = "completed"
				}
			}
		}
	}
	out := make([]templates.RunPhaseCard, 0, len(order))
	for _, name := range order {
		out = append(out, *phaseByName[name])
	}
	return out
}

// jsonField does a tiny scan of a JSON-encoded payload for a top-level
// string field. Saves us a json.Unmarshal allocation; falls back to empty.
func jsonField(payload, key string) string {
	var m map[string]any
	if err := jsonUnmarshalCompat(payload, &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func jsonUnmarshalCompat(s string, v any) error {
	if s == "" {
		return errors.New("empty json")
	}
	return jsonUnmarshal([]byte(s), v)
}

func jsonUnmarshal(b []byte, v any) error {
	// dedicated wrapper so we can replace the json impl in the future without
	// touching every call site.
	return jsonPkgUnmarshal(b, v)
}

// FindingsList renders /repos/{repo_id}/findings.
func (h *RepoHandler) FindingsList(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if repoID == "" {
		repoID = pathParam(r.URL.Path, "/repos/")
		if i := strings.Index(repoID, "/"); i >= 0 {
			repoID = repoID[:i]
		}
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
		Severity:     r.URL.Query().Get("severity"),
		Status:       r.URL.Query().Get("status"),
		Path:         r.URL.Query().Get("path"),
		CWE:          r.URL.Query().Get("cwe"),
		Agent:        r.URL.Query().Get("agent"),
		ReopenedOnly: r.URL.Query().Get("reopened") == "1",
		DateFrom:     r.URL.Query().Get("from"),
		DateTo:       r.URL.Query().Get("to"),
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

// RunCancel handles POST /repos/{repo_id}/runs/{run_id}/cancel — flips the
// run row to 'cancelled'; the worker observes via the cancel-poller in
// run_pr.go and tears the container down.
func (h *RepoHandler) RunCancel(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	runID := r.PathValue("run_id")
	if repoID == "" || runID == "" {
		http.Error(w, "missing path values", http.StatusBadRequest)
		return
	}
	run, err := h.Stores.Runs.Get(r.Context(), runID)
	if err != nil || run.RepoID != repoID {
		http.NotFound(w, r)
		return
	}
	if err := h.Stores.Runs.Cancel(r.Context(), runID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/repos/"+repoID+"/runs/"+runID, http.StatusSeeOther)
}

// FindingDetail renders /repos/{repo_id}/findings/{finding_id}.
func (h *RepoHandler) FindingDetail(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	findingID := r.PathValue("finding_id")
	if repoID == "" || findingID == "" {
		http.NotFound(w, r)
		return
	}
	repo, err := h.Stores.Repos.Get(r.Context(), repoID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	row, err := h.Stores.Findings.Get(r.Context(), findingID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if row.RepoID != repo.ID {
		http.NotFound(w, r)
		return
	}
	actions, _ := h.Stores.FindingActions.List(r.Context(), findingID)
	navRepos, _ := h.allRepos(r.Context())
	v := templates.FindingDetailView{
		Page:    pageData(r, row.Title, navRepos),
		Repo:    repo,
		Finding: row,
		Actions: actions,
	}
	renderHTML(w, r, templates.FindingDetail(v))
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
		if f.CWE != "" && !strings.EqualFold(r.CWE, f.CWE) {
			continue
		}
		if f.Path != "" && !strings.Contains(r.File, f.Path) {
			continue
		}
		if f.Agent != "" && !strings.EqualFold(r.CreatedBy, f.Agent) {
			continue
		}
		if f.ReopenedOnly && r.ReopenedCount == 0 {
			continue
		}
		if f.DateFrom != "" {
			if t, err := time.Parse("2006-01-02", f.DateFrom); err == nil && r.CreatedAt.Before(t) {
				continue
			}
		}
		if f.DateTo != "" {
			if t, err := time.Parse("2006-01-02", f.DateTo); err == nil && r.CreatedAt.After(t.AddDate(0, 0, 1)) {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
