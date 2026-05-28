package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/web/templates"
	"github.com/diffsec/quokka/internal/web/webctx"
)

// renderHTML sets the html content-type and renders a templ component.
func renderHTML(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := c.Render(r.Context(), w); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

func pageData(r *http.Request, title string, navRepos []*store.Repository) templates.PageData {
	return templates.PageData{
		Title:     title,
		User:      webctx.UserFromCtx(r.Context()),
		CSRFToken: webctx.CSRFTokenFromCtx(r.Context()),
		NavRepos:  navRepos,
	}
}

// pathParam extracts the value immediately after the given prefix, stopping at
// the next '/'. Empty string when prefix doesn't match.
func pathParam(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := path[len(prefix):]
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// splitRunPath parses /repos/{repo}/runs/{run} into (repo, run).
func splitRunPath(path string) (string, string) {
	const prefix = "/repos/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}
	rest := path[len(prefix):]
	idx := strings.Index(rest, "/")
	if idx < 0 {
		return "", ""
	}
	repoID := rest[:idx]
	rest = rest[idx+1:]
	if !strings.HasPrefix(rest, "runs/") {
		return "", ""
	}
	runID := rest[len("runs/"):]
	if i := strings.Index(runID, "/"); i >= 0 {
		runID = runID[:i]
	}
	return repoID, runID
}

func atoiSafe(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// singleOrgID returns the only organizations row. Brief says "one org per
// instance"; we never fan out by tenant.
func singleOrgID(ctx context.Context, stores *store.Stores) (string, error) {
	orgs, err := stores.Orgs.List(ctx)
	if err != nil {
		return "", err
	}
	if len(orgs) == 0 {
		return "", errors.New("no organization rows")
	}
	return orgs[0].ID, nil
}
