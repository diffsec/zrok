package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	_ "github.com/diffsec/quokka/internal/llm/anthropic"
	_ "github.com/diffsec/quokka/internal/llm/openai"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/agentloop/tools"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/storerpc"
	"github.com/diffsec/quokka/internal/workflow"
	"github.com/diffsec/quokka/internal/worker/jobs"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Agent runtime sidecar commands",
	}
	var jobFile string
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run an agent inside a container against /workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgentSidecarFromFile(cmd.Context(), jobFile, cmd.OutOrStdout())
		},
	}
	runCmd.Flags().StringVar(&jobFile, "job-file", "/job/spec.json",
		"Path to the job spec JSON file the container was launched with")
	cmd.AddCommand(runCmd)
	return cmd
}

// runAgentSidecarFromFile is the production entrypoint: it reads the
// spec, dials the host's RPC socket, builds an executor, and drives it.
func runAgentSidecarFromFile(ctx context.Context, jobFile string, w io.Writer) error {
	data, err := os.ReadFile(jobFile)
	if err != nil {
		return fmt.Errorf("read job file %s: %w", jobFile, err)
	}
	var spec jobs.JobSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("parse job spec: %w", err)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	client, err := storerpc.Dial(spec.RPCSocket, spec.RPCToken)
	if err != nil {
		return fmt.Errorf("dial rpc socket: %w", err)
	}
	defer client.Close()
	return RunSidecar(ctx, &spec, client, NewEnvProviderFactory(&spec), w)
}

// ProviderFactory builds an llm.Provider for the active model config.
type ProviderFactory func(modelCfg *agent.ModelConfig) (llm.Provider, error)

// RunSidecar drives the workflow.Executor end-to-end. Exported so the
// jobs_test variant can call it with an in-process RPC pair and a fake
// provider factory — that's how we exercise the real executor without
// Docker.
func RunSidecar(ctx context.Context, spec *jobs.JobSpec, client *storerpc.Client, providerFactory ProviderFactory, w io.Writer) error {
	if err := spec.Validate(); err != nil {
		return err
	}

	// Build a synthetic Stores aggregate where the only populated
	// stores are the RPC-backed ones tools need. Everything else stays
	// nil so a tool reaching for an unsupported store fails loudly.
	rpcStores := &store.Stores{
		Findings:   client.Findings(),
		Memories:   client.Memories(),
		Exceptions: client.Exceptions(),
	}

	sink := newStdoutSink(spec.RunID, w)

	// Resolve the workflow YAML.
	wf, err := workflow.Parse([]byte(spec.WorkflowYAML))
	if err != nil {
		return fmt.Errorf("parse workflow: %w", err)
	}

	// Build the AgentLookup from the spec's resolved set, falling back
	// to the built-in registry when an agent isn't in the spec.
	lookup := buildAgentLookup(spec)

	registry := tools.Default()

	workspaceDir := spec.WorkspaceDir
	if workspaceDir == "" {
		workspaceDir = "/workspace"
	}
	sandbox := tools.NewSandbox(workspaceDir)

	exec := &workflow.Executor{
		Stores:          rpcStores,
		ToolRegistry:    registry,
		ProviderFactory: workflow.ProviderFactory(providerFactory),
		AgentLookup:     lookup,
		Sink:            sink,
		Project:         spec.ProjectMeta,
		Classification:  spec.Classification,
		Sandbox:         sandbox,
		SpawnDefaults: tools.SpawnDefaults{
			MaxIters:     spec.MaxIters,
			MaxTokensRun: spec.MaxTokensRun,
		},
	}

	rc := workflow.RunContext{
		RepoID:       spec.RepoID,
		RunID:        spec.RunID,
		HeadSHA:      spec.HeadSHA,
		BaseSHA:      spec.BaseSHA,
		ChangedFiles: spec.ChangedFiles,
		Repo:         spec.RepoFullName,
	}

	if err := exec.Run(ctx, wf, rc); err != nil {
		// Emit a final error event so the host's drainLogs sees it.
		sink.Emit(agentloop.TranscriptEvent{
			RunID:     spec.RunID,
			AgentName: "sidecar",
			Timestamp: time.Now(),
			Kind:      agentloop.KindError,
			Payload:   map[string]string{"error": err.Error()},
		})
		return err
	}
	return nil
}

// buildAgentLookup returns a function that looks up agents by name from
// the spec, falling back to the built-in registry. Project-level
// overrides land in spec.Agents; everything else (sub-agents spawned via
// spawn_agent) goes through agent.GetBuiltinAgent.
func buildAgentLookup(spec *jobs.JobSpec) workflow.AgentLookup {
	specMap := make(map[string]agent.AgentConfig, len(spec.Agents))
	for _, a := range spec.Agents {
		cfg := a.Config
		// Materialize the per-agent ModelConfig from the spec if the
		// embedded config didn't carry one.
		if cfg.ModelConfig == nil && a.ModelConfig != nil {
			mc := *a.ModelConfig
			cfg.ModelConfig = &mc
		}
		specMap[a.Name] = cfg
	}
	return func(name string) (*agent.AgentConfig, error) {
		if cfg, ok := specMap[name]; ok {
			c := cfg
			return &c, nil
		}
		if cfg := agent.GetBuiltinAgent(name); cfg != nil {
			return cfg, nil
		}
		return nil, fmt.Errorf("agent %q not found in spec or built-in registry", name)
	}
}

// stdoutSink is an EventSink that writes each event as one NDJSON line
// to the underlying io.Writer. Used by the sidecar to stream transcript
// events to container stdout for the host's drainLogs to ingest.
type stdoutSink struct {
	runID string
	w     io.Writer
	seq   atomic.Int64
}

func newStdoutSink(runID string, w io.Writer) *stdoutSink {
	return &stdoutSink{runID: runID, w: w}
}

func (s *stdoutSink) Emit(ev agentloop.TranscriptEvent) {
	if s == nil || s.w == nil {
		return
	}
	if ev.RunID == "" {
		ev.RunID = s.runID
	}
	if ev.Seq == 0 {
		ev.Seq = int(s.seq.Add(1))
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	line, err := json.Marshal(map[string]any{
		"run_id":     ev.RunID,
		"agent_name": ev.AgentName,
		"seq":        ev.Seq,
		"ts":         ev.Timestamp.Format(time.RFC3339Nano),
		"kind":       string(ev.Kind),
		"payload":    ev.Payload,
	})
	if err != nil {
		return
	}
	line = append(line, '\n')
	_, _ = s.w.Write(line)
}

// NewEnvProviderFactory returns a ProviderFactory backed by the
// QUOKKA_PROVIDER_<LABEL>_* env vars the host worker injects. The
// factory resolves the provider in this order:
//
//  1. If modelCfg.ProviderID is non-empty, look up that label.
//  2. Otherwise, fall back to spec.DefaultProviderLabel.
//
// The resolved label is upper-cased and used to read KEY/BASE_URL/PROTOCOL.
func NewEnvProviderFactory(spec *jobs.JobSpec) ProviderFactory {
	return func(modelCfg *agent.ModelConfig) (llm.Provider, error) {
		label := ""
		if modelCfg != nil && modelCfg.ProviderID != "" {
			label = modelCfg.ProviderID
		}
		if label == "" {
			label = spec.DefaultProviderLabel
		}
		if label == "" {
			return nil, errors.New("provider: no provider label configured")
		}
		upper := strings.ToUpper(label)
		key := os.Getenv("QUOKKA_PROVIDER_" + upper + "_KEY")
		baseURL := os.Getenv("QUOKKA_PROVIDER_" + upper + "_BASE_URL")
		protocol := os.Getenv("QUOKKA_PROVIDER_" + upper + "_PROTOCOL")
		if key == "" {
			return nil, fmt.Errorf("provider %q: env QUOKKA_PROVIDER_%s_KEY is empty", label, upper)
		}
		if protocol == "" {
			// Default to anthropic when not set — keeps the dev path
			// short when only ANTHROPIC_API_KEY is injected.
			protocol = "anthropic"
		}
		cfg := &llm.Config{
			ProviderID: protocol,
			BaseURL:    baseURL,
			APIKey:     key,
		}
		if modelCfg != nil {
			if modelCfg.Model != "" {
				cfg.DefaultModel = modelCfg.Model
			}
			if modelCfg.Temperature != 0 {
				cfg.Temperature = modelCfg.Temperature
			}
			if modelCfg.MaxTokens != 0 {
				cfg.MaxTokens = modelCfg.MaxTokens
			}
		}
		return llm.NewProvider(cfg)
	}
}

