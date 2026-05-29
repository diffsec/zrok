// Package workflow defines the orchestrator schema: a versioned YAML
// document of ordered phases, each with an agents[] list and an optional
// templated prompt-hook fragment. Parsing is strict; the executor is
// in-process and storage-agnostic — PR-4 wires DB persistence.
package workflow

// Mode controls how agents within a phase execute.
type Mode string

const (
	ModeSequential Mode = "sequential"
	ModeParallel   Mode = "parallel"
)

// PromptHookTemplate is the keyword on Phase.PromptHookTemplate that
// triggers the per-finding fanout expansion.
const PromptHookTemplatePerFinding = "per_finding"

// Workflow is the top-level YAML document.
type Workflow struct {
	Name    string  `yaml:"name"`
	Version int     `yaml:"version"`
	Phases  []Phase `yaml:"phases"`
}

// Phase is one stage of the workflow.
type Phase struct {
	Name        string `yaml:"name"`
	Mode        Mode   `yaml:"mode"`
	MaxParallel int    `yaml:"max_parallel,omitempty"`
	// Agents is the list of agent names this phase considers. The
	// executor filters this list by applicability before constructing
	// child Specs.
	Agents []string `yaml:"agents"`
	// PromptHook is a text/template fragment rendered with the run
	// context (.ChangedFiles, .Repo, .HeadSHA, .RunID) before being
	// injected into each agent's system prompt.
	PromptHook string `yaml:"prompt_hook,omitempty"`
	// PromptHookTemplate is a reserved-keyword expansion (e.g.
	// "per_finding"). When non-empty it overrides PromptHook.
	PromptHookTemplate string `yaml:"prompt_hook_template,omitempty"`
	// SeverityThreshold filters the findings the per_finding template
	// considers. Defaults to "medium" when blank.
	SeverityThreshold string `yaml:"severity_threshold,omitempty"`
}

// RunContext is the per-run data the executor renders prompt-hook
// templates against.
type RunContext struct {
	RepoID       string
	RunID        string
	HeadSHA      string
	BaseSHA      string
	ChangedFiles []string
	Repo         string
}
