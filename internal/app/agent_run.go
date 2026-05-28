package app

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/spf13/cobra"
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
			return runAgentSidecar(jobFile, cmd.OutOrStdout())
		},
	}
	runCmd.Flags().StringVar(&jobFile, "job-file", "/job/spec.json",
		"Path to the job spec JSON file the container was launched with")
	cmd.AddCommand(runCmd)
	return cmd
}

// JobSpec is what the host worker writes into /job/spec.json. PR-4 ships a
// minimal v0 shape: the runner just emits a couple of NDJSON transcript
// lines so the host can verify the wire format end-to-end. PR-5/6 expand
// this to drive the full workflow.Executor in-process.
type JobSpec struct {
	RunID  string `json:"run_id"`
	RepoID string `json:"repo_id"`
}

func runAgentSidecar(jobFile string, w interface{ Write([]byte) (int, error) }) error {
	data, err := os.ReadFile(jobFile)
	if err != nil {
		return fmt.Errorf("read job file %s: %w", jobFile, err)
	}
	var spec JobSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("parse job spec: %w", err)
	}
	if spec.RunID == "" {
		return fmt.Errorf("job spec: run_id is required")
	}
	emit := func(kind agentloop.EventKind, payload any) error {
		line, _ := json.Marshal(map[string]any{
			"run_id":  spec.RunID,
			"agent_name": "sidecar",
			"seq":     0,
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"kind":    string(kind),
			"payload": payload,
		})
		line = append(line, '\n')
		_, err := w.Write(line)
		return err
	}
	if err := emit(agentloop.KindAgentStart, map[string]any{"agent": "sidecar"}); err != nil {
		return err
	}
	if err := emit(agentloop.KindAssistantText, "PR-4 sidecar stub: workspace=/workspace state=/state"); err != nil {
		return err
	}
	if err := emit(agentloop.KindAgentEnd, map[string]any{"agent": "sidecar"}); err != nil {
		return err
	}
	return nil
}
