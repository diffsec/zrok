package templates

import (
	"time"

	"github.com/diffsec/quokka/internal/store"
)

// PageData carries the chrome-level fields every page needs (current user,
// CSRF token, app-wide nav). Each page-specific view type embeds this.
type PageData struct {
	Title     string
	User      *store.User
	CSRFToken string
	NavRepos  []*store.Repository
}

// LoginView seeds the login page.
type LoginView struct {
	Error     string
	Next      string
	CSRFToken string
}

// ReposView seeds /repos.
type ReposView struct {
	Page  PageData
	Repos []*store.Repository
}

// RepoOverviewView seeds /repos/{id}.
type RepoOverviewView struct {
	Page              PageData
	Repo              *store.Repository
	RecentRuns        []*store.Run
	OpenFindingsBySev map[string]int
}

// RunsListView seeds /repos/{id}/runs.
type RunsListView struct {
	Page   PageData
	Repo   *store.Repository
	Runs   []*store.Run
	Limit  int
	Offset int
	Total  int
}

// RunView seeds /repos/{id}/runs/{id}.
type RunView struct {
	Page     PageData
	Repo     *store.Repository
	Run      *store.Run
	Findings []*store.FindingRow
}

// FindingsListView seeds /repos/{id}/findings.
type FindingsListView struct {
	Page     PageData
	Repo     *store.Repository
	Findings []*store.FindingRow
	Filter   FindingFilter
}

// FindingFilter mirrors the read-only query-string filters supported by the
// minimal PR-3 findings list. PR-5 expands this with bulk-action endpoints.
type FindingFilter struct {
	Severity string
	Status   string
	Path     string
	CWE      string
	Agent    string
}

// FormatTimeAgo returns a short human duration for a timestamp.
func FormatTimeAgo(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return durationLabel(d/time.Minute, "min")
	case d < 24*time.Hour:
		return durationLabel(d/time.Hour, "h")
	default:
		return durationLabel(d/(24*time.Hour), "d")
	}
}

func durationLabel(d time.Duration, unit string) string {
	if d == 1 {
		return "1 " + unit
	}
	return intToString(int(d)) + " " + unit
}

func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
