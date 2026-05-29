package templates

import (
	"fmt"
	"strings"
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
	Phases   []RunPhaseCard
}

// RunPhaseCard is one vertical card on the timeline.
type RunPhaseCard struct {
	Name   string
	Status string // queued | running | completed | failed
	Agents []RunAgentCard
}

// RunAgentCard is a single agent card inside a phase card.
type RunAgentCard struct {
	Slot   string // stable id for SSE swaps; we use agent_name today
	Name   string
	Status string
	Tokens int
	Cost   float64
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
	Severity     string
	Status       string
	Path         string
	CWE          string
	Agent        string
	ReopenedOnly bool
	DateFrom     string
	DateTo       string
}

// ModalView is the shared shape for every triage modal.
type ModalView struct {
	RepoID       string
	FindingID    string
	CSRFToken    string
	DefaultUntil string
	Suppress     SuppressPrefill
}

// SuppressPrefill carries the suggested axis values seeded from the finding.
type SuppressPrefill struct {
	Fingerprint string
	PathGlob    string
	CWE         string
}

// FindingDetailView seeds /repos/{id}/findings/{fid}.
type FindingDetailView struct {
	Page    PageData
	Repo    *store.Repository
	Finding *store.FindingRow
	Actions []*store.FindingAction
}

// RepoSettingsView seeds /repos/{id}/settings.
type RepoSettingsView struct {
	Page      PageData
	Repo      *store.Repository
	Settings  *store.PRFeedbackSettings
	Workflows []*store.Workflow
}

// ProvidersListView seeds /providers.
type ProvidersListView struct {
	Page      PageData
	Providers []*store.Provider
}

// ProviderWizardView seeds /providers/new.
type ProviderWizardView struct {
	Page    PageData
	Presets []ProviderPreset
	Error   string
}

// ProviderPreset is one row in the wizard's preset shortcut grid.
type ProviderPreset struct {
	Key      string // anthropic, openai, openrouter, nanogpt, ollama, groq, together, custom
	Label    string
	Protocol string // anthropic | openai-compatible
	BaseURL  string
}

// ProviderDetailView seeds /providers/{id}.
type ProviderDetailView struct {
	Page     PageData
	Provider *store.Provider
	Models   []*store.ProviderModel
	TestResp string
}

// AgentsListView seeds /agents.
type AgentsListView struct {
	Page   PageData
	Agents []*store.AgentConfigRow
}

// AgentEditorView seeds /agents/{name}.
type AgentEditorView struct {
	Page             PageData
	Name             string
	IsNew            bool
	Description      string
	Phase            string
	PromptTemplate   string
	ToolsAllowed     []string
	AllToolNames     []string
	ProjectTypes     []string
	ProjectTraits    []string
	OwnsCWEs         []string
	ContextMemories  []string
	AlwaysInclude    bool
	Providers        []*store.Provider
	ModelProviderID  string
	ModelName        string
	Temperature      float32
	MaxTokens        int
	Revisions        []*store.AgentConfigRevision
	CurrentRevision  int
	ReadOnly         bool
	Error            string
	YAMLPreview      string
	ConnectedRepos   []*store.Repository
}

// CommitModalView seeds /agents/{name}/commit modal.
type CommitModalView struct {
	AgentName string
	CSRFToken string
	Repos     []*store.Repository
}

// WorkflowsListView seeds /workflows.
type WorkflowsListView struct {
	Page      PageData
	Workflows []*store.Workflow
}

// WorkflowEditorView seeds /workflows/{id}.
type WorkflowEditorView struct {
	Page          PageData
	Workflow      *store.Workflow
	Version       *store.WorkflowVersion
	YAML          string
	Error         string
	AvailableAgents []string
}

// SettingsView seeds /settings (org-level).
type SettingsView struct {
	Page             PageData
	Providers        []*store.Provider
	AllProviderModels map[string][]*store.ProviderModel
	OrgName          string
	DefaultOrch      string
	DefaultAnalysis  string
	DefaultValidation string
	Maintenance      bool
}

// UsersListView seeds /users.
type UsersListView struct {
	Page  PageData
	Users []*store.User
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

// defaultSuppressExpiry returns the YYYY-MM-DD string 90 days from now.
func defaultSuppressExpiry() string {
	return time.Now().AddDate(0, 0, 90).Format("2006-01-02")
}

// itoa is a thin wrapper so templates can render ints without importing strconv.
func itoa(n int) string { return intToString(n) }

// floatStr formats a float32 for display, trimming trailing zeros.
func floatStr(f float32) string {
	if f == 0 {
		return "0"
	}
	s := fmt.Sprintf("%.3f", f)
	for strings.HasSuffix(s, "0") {
		s = s[:len(s)-1]
	}
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	return s
}

// knownProjectTypesForUI returns the registry minus already-selected entries.
func knownProjectTypesForUI(selected []string) []string {
	all := []string{"web-app", "api-service", "cli-tool", "library", "worker"}
	return minusSet(all, selected)
}

func knownProjectTraitsForUI(selected []string) []string {
	all := []string{"has-datastore", "has-auth", "has-infrastructure", "has-sensitive-data", "has-external-apis"}
	return minusSet(all, selected)
}

func minusSet(all, selected []string) []string {
	sel := map[string]bool{}
	for _, s := range selected {
		sel[s] = true
	}
	out := make([]string, 0, len(all))
	for _, a := range all {
		if !sel[a] {
			out = append(out, a)
		}
	}
	return out
}

// presetsJSON encodes the providers preset slice into a JSON object keyed by
// preset.Key. Used by Alpine to swap protocol + baseURL on preset change.
func presetsJSON(presets []ProviderPreset) string {
	if len(presets) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range presets {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:{\"protocol\":%q,\"baseURL\":%q}", p.Key, p.Protocol, p.BaseURL)
	}
	b.WriteByte('}')
	return b.String()
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
