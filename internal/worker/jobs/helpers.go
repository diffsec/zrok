package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/store"
)

// defaultWorkflowYAML is the workflow the worker uses when an org has no
// configured workflow rows. Keeping it tiny — recon → reporting — keeps
// the test footprint small but exercises the executor end-to-end.
const defaultWorkflowYAML = `
name: default
version: 1
phases:
  - name: recon
    mode: sequential
    agents:
      - recon-agent
  - name: reporting
    mode: sequential
    agents:
      - review-agent
`

// resolveWorkflowYAML returns the workflow YAML for repo. Prefers the
// org's configured workflow; falls back to defaultWorkflowYAML.
func resolveWorkflowYAML(ctx context.Context, deps *Deps, orgID, repoID string) string {
	if deps.Stores == nil || deps.Stores.Workflows == nil {
		return defaultWorkflowYAML
	}
	_, ver, err := deps.Stores.Workflows.GetActiveForRepo(ctx, orgID, repoID)
	if err != nil || ver == nil || strings.TrimSpace(ver.YAML) == "" {
		return defaultWorkflowYAML
	}
	return ver.YAML
}

// resolveAgents returns the resolved AgentSpec list. PR-4.5 reads only
// the built-in registry — AgentConfigStore is a stub today. The active
// providerLabel is attached to every agent so the sidecar can look up
// the env-injected key.
func resolveAgents(_ context.Context, _ *Deps, providerLabel string) []AgentSpec {
	configs := agent.GetBuiltinAgents()
	out := make([]AgentSpec, 0, len(configs))
	for _, c := range configs {
		cfg := c
		out = append(out, AgentSpec{
			Name:          cfg.Name,
			Config:        cfg,
			ProviderLabel: providerLabel,
			ModelConfig:   cfg.ModelConfig,
		})
	}
	return out
}

// resolveDefaultProvider returns the default provider label, its
// protocol (anthropic|openai-compat), the base URL, and the decrypted
// API key. PR-4.5 looks up the org's `is_default=true` provider when
// present; otherwise it returns ambient env vars so dev setups keep
// working with `ANTHROPIC_API_KEY` in the worker's env.
//
// The label is what the sidecar uppercases to read QUOKKA_PROVIDER_<L>_*.
func resolveDefaultProvider(ctx context.Context, deps *Deps, orgID string) (label, protocol, baseURL, key string, err error) {
	if deps.Stores != nil && deps.Stores.Providers != nil {
		providers, lerr := deps.Stores.Providers.List(ctx, orgID)
		if lerr == nil {
			for _, p := range providers {
				if p.IsDefault {
					return strings.ToLower(p.Name), p.Protocol, p.BaseURL, p.APIKey, nil
				}
			}
			// No default — pick the first.
			if len(providers) > 0 {
				p := providers[0]
				return strings.ToLower(p.Name), p.Protocol, p.BaseURL, p.APIKey, nil
			}
		}
	}
	// Dev fallback: ambient env. The worker reads its own process env
	// so single-tenant dev setups with ANTHROPIC_API_KEY work without
	// seeding a provider row.
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return "default", "anthropic", "", key, nil
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return "default", "openai-compat", "", key, nil
	}
	// Empty key — sidecar's NewEnvProviderFactory will surface the
	// "env key empty" error the first time a provider is requested.
	return "default", "anthropic", "", "", nil
}

// generateRPCToken returns a fresh 32-byte hex secret.
func generateRPCToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// buildJobSpec assembles the full JobSpec the runner container reads.
// rpcSocket is the host-side socket path; rpcToken is the shared
// secret. The provider env injection happens in jobSpecToContainerSpec
// so this function is pure.
func buildJobSpec(
	ctx context.Context,
	deps *Deps,
	repo *store.Repository,
	run *store.Run,
	pr github.RunPRPayload,
	rpcSocketHost, rpcToken string,
) (JobSpec, ProviderResolution, error) {
	providerLabel, protocol, baseURL, key, err := resolveDefaultProvider(ctx, deps, repo.OrgID)
	if err != nil {
		return JobSpec{}, ProviderResolution{}, fmt.Errorf("resolve provider: %w", err)
	}

	wfYAML := resolveWorkflowYAML(ctx, deps, repo.OrgID, repo.ID)
	agents := resolveAgents(ctx, deps, providerLabel)

	classification := project.ProjectClassification{}
	if repo.ClassificationJSON != "" {
		_ = json.Unmarshal([]byte(repo.ClassificationJSON), &classification)
	}

	spec := JobSpec{
		SpecVersion:          1,
		RunID:                run.ID,
		RepoID:               repo.ID,
		OrgID:                repo.OrgID,
		PRNumber:             pr.PRNumber,
		BaseSHA:              pr.BaseSHA,
		HeadSHA:              pr.HeadSHA,
		RepoFullName:         pr.RepoFullName,
		ChangedFiles:         nil, // diff resolution lands in PR-5
		WorkspaceDir:         "/workspace",
		StateDir:             "/state",
		RPCSocket:            "/var/run/quokka.sock",
		RPCToken:             rpcToken,
		Classification:       classification,
		WorkflowYAML:         wfYAML,
		Agents:               agents,
		DefaultProviderLabel: providerLabel,
	}
	return spec, ProviderResolution{
		Label:    providerLabel,
		Protocol: protocol,
		BaseURL:  baseURL,
		APIKey:   key,
	}, nil
}

// ProviderResolution is the decrypted provider tuple the host injects
// into the container as env vars. Kept narrow so the API surface is
// obvious — the worker never logs APIKey.
type ProviderResolution struct {
	Label    string
	Protocol string
	BaseURL  string
	APIKey   string
}

// containerSpecFromJobSpec builds the ContainerSpec for a JobSpec +
// provider tuple. The RPC socket file at hostSocketPath must already
// exist; the worker creates it before calling.
func containerSpecFromJobSpec(
	deps *Deps,
	spec JobSpec,
	provider ProviderResolution,
	repoPath string,
	hostSocketPath string,
) (container.ContainerSpec, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return container.ContainerSpec{}, fmt.Errorf("encode job spec: %w", err)
	}
	statePath := ""
	if deps.DataRoot != "" {
		statePath = deps.DataRoot + "/state/" + spec.RepoID
	}
	upper := strings.ToUpper(provider.Label)
	env := map[string]string{
		"QUOKKA_RUN_ID":     spec.RunID,
		"QUOKKA_REPO_ID":    spec.RepoID,
		"QUOKKA_ORG_ID":     spec.OrgID,
		"QUOKKA_RPC_SOCKET": spec.RPCSocket,
		"QUOKKA_RPC_TOKEN":  spec.RPCToken,
	}
	if provider.APIKey != "" {
		env["QUOKKA_PROVIDER_"+upper+"_KEY"] = provider.APIKey
	}
	if provider.BaseURL != "" {
		env["QUOKKA_PROVIDER_"+upper+"_BASE_URL"] = provider.BaseURL
	}
	if provider.Protocol != "" {
		env["QUOKKA_PROVIDER_"+upper+"_PROTOCOL"] = provider.Protocol
	}
	return container.ContainerSpec{
		Image:       deps.RunnerImage,
		JobSpecJSON: b,
		RepoPath:    repoPath,
		StatePath:   statePath,
		Env:         env,
		SocketBindMounts: []container.SocketMount{
			{HostPath: hostSocketPath, ContainerPath: spec.RPCSocket},
		},
		Resources: container.DefaultResources(),
	}, nil
}

// parseTranscriptLine extracts a TranscriptEvent from a runner NDJSON line.
// Lines that don't match are returned with the raw line as Payload.
func parseTranscriptLine(runID, line string) agentloop.TranscriptEvent {
	var w struct {
		RunID     string `json:"run_id"`
		AgentName string `json:"agent_name"`
		Seq       int    `json:"seq"`
		Timestamp string `json:"ts"`
		Kind      string `json:"kind"`
		Payload   any    `json:"payload"`
	}
	if err := json.Unmarshal([]byte(line), &w); err != nil {
		return agentloop.TranscriptEvent{RunID: runID, Kind: "raw", Payload: line, Timestamp: time.Now()}
	}
	t, _ := time.Parse(time.RFC3339Nano, w.Timestamp)
	if t.IsZero() {
		t = time.Now()
	}
	rid := w.RunID
	if rid == "" {
		rid = runID
	}
	return agentloop.TranscriptEvent{
		RunID:     rid,
		AgentName: w.AgentName,
		Seq:       w.Seq,
		Timestamp: t,
		Kind:      agentloop.EventKind(w.Kind),
		Payload:   w.Payload,
	}
}

// toGitHubFindings narrows the store.FindingRow set to the subset the
// feedback writers consume.
func toGitHubFindings(fs []*store.FindingRow) []github.Finding {
	out := make([]github.Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, github.Finding{
			Title:       f.Title,
			Severity:    f.Severity,
			CWE:         f.CWE,
			File:        f.File,
			LineStart:   f.LineStart,
			Description: f.Description,
			Remediation: f.Remediation,
		})
	}
	return out
}

// summarizeFindings renders the summary comment body.
func summarizeFindings(fs []*store.FindingRow) string {
	if len(fs) == 0 {
		return "Quokka completed. No new findings."
	}
	by := map[string]int{}
	for _, f := range fs {
		by[strings.ToLower(f.Severity)]++
	}
	var sb strings.Builder
	sb.WriteString("Quokka findings on this PR\n\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if by[sev] > 0 {
			fmt.Fprintf(&sb, "- %s: %d\n", sev, by[sev])
		}
	}
	sb.WriteString("\nSee the run for details.\n")
	return sb.String()
}

// buildInlineComments turns findings into review comments. Position
// resolution is left to the feedback layer when a diff is available; in
// PR-4 we use line as a fallback (PR-5 wires the real diff parse).
func buildInlineComments(fs []*store.FindingRow) []github.ReviewComment {
	out := make([]github.ReviewComment, 0, len(fs))
	for _, f := range fs {
		if f.File == "" || f.LineStart <= 0 {
			continue
		}
		body := fmt.Sprintf("**%s**: %s", strings.ToUpper(f.Severity), f.Title)
		if f.Description != "" {
			body += "\n\n" + f.Description
		}
		out = append(out, github.ReviewComment{
			Path:     f.File,
			Position: f.LineStart, // will be replaced with diff position when caller has a diff
			Body:     body,
		})
	}
	return out
}

