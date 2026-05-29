package jobs

import (
	"fmt"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/project"
)

// JobSpec is the shape the host worker writes into /job/spec.json and the
// in-container sidecar reads on boot. Anything the executor needs that
// can't come over the RPC socket lives here.
//
// This is the contract between the worker and the sidecar; keep changes
// backward compatible (additive fields only) once the binary ships.
type JobSpec struct {
	// SpecVersion is a monotonic schema version. PR-4.5 ships v1.
	SpecVersion int `json:"spec_version"`

	// Identity for the run.
	RunID  string `json:"run_id"`
	RepoID string `json:"repo_id"`
	OrgID  string `json:"org_id"`

	// PR context the executor renders into prompt hooks.
	PRNumber     int      `json:"pr_number"`
	BaseSHA      string   `json:"base_sha"`
	HeadSHA      string   `json:"head_sha"`
	RepoFullName string   `json:"repo_full_name"`
	ChangedFiles []string `json:"changed_files,omitempty"`

	// In-container paths. Always /workspace and /state in prod; tests
	// override.
	WorkspaceDir string `json:"workspace_dir"`
	StateDir     string `json:"state_dir"`

	// RPC socket the sidecar dials and the token it must present. The
	// host worker generates a fresh token per run.
	RPCSocket string `json:"rpc_socket"`
	RPCToken  string `json:"rpc_token"`

	// Classification drives Executor.filterAgents — agents whose
	// applicability rules don't match these project types/traits are
	// skipped per phase.
	Classification project.ProjectClassification `json:"classification"`

	// Project metadata the prompt generator reads.
	ProjectMeta *project.Project `json:"project_meta,omitempty"`

	// Workflow is the YAML body the executor parses. Embedded inline so
	// the sidecar doesn't have to know how to fetch versions.
	WorkflowYAML string `json:"workflow_yaml"`

	// Agents is the resolved set the executor's AgentLookup serves. The
	// worker resolves org-level overrides before writing; the sidecar
	// just consults this slice.
	Agents []AgentSpec `json:"agents"`

	// DefaultProviderLabel is the env-var label of the org's default
	// provider. The sidecar reads QUOKKA_PROVIDER_<UPPER_LABEL>_* env
	// vars to construct the llm.Provider when an agent's ModelConfig
	// doesn't supply its own ProviderID.
	DefaultProviderLabel string `json:"default_provider_label"`

	// MaxIters / MaxTokensRun are the SpawnDefaults the executor passes
	// through. Zero means "use loop defaults".
	MaxIters     int `json:"max_iters,omitempty"`
	MaxTokensRun int `json:"max_tokens_run,omitempty"`
}

// AgentSpec is one agent entry in the spec. The YAML and the
// ProviderLabel together let the sidecar reconstitute the
// agent.AgentConfig + an llm.Provider without touching the host's DB.
type AgentSpec struct {
	Name          string             `json:"name"`
	Config        agent.AgentConfig  `json:"config"`
	ProviderLabel string             `json:"provider_label,omitempty"`
	ModelConfig   *agent.ModelConfig `json:"model_config,omitempty"`
}

// Validate enforces the minimum required fields. The sidecar runs this
// on boot to fail fast on a malformed spec.
func (s *JobSpec) Validate() error {
	if s == nil {
		return fmt.Errorf("job spec: nil")
	}
	if s.SpecVersion == 0 {
		return fmt.Errorf("job spec: spec_version is required")
	}
	if s.RunID == "" {
		return fmt.Errorf("job spec: run_id is required")
	}
	if s.RepoID == "" {
		return fmt.Errorf("job spec: repo_id is required")
	}
	if s.OrgID == "" {
		return fmt.Errorf("job spec: org_id is required")
	}
	if s.WorkspaceDir == "" {
		return fmt.Errorf("job spec: workspace_dir is required")
	}
	if s.RPCSocket == "" {
		return fmt.Errorf("job spec: rpc_socket is required")
	}
	if s.RPCToken == "" {
		return fmt.Errorf("job spec: rpc_token is required")
	}
	if s.WorkflowYAML == "" {
		return fmt.Errorf("job spec: workflow_yaml is required")
	}
	return nil
}
