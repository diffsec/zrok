package app_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/app"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/llm/fake"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	"github.com/diffsec/quokka/internal/storerpc"
	"github.com/diffsec/quokka/internal/worker/jobs"
)

func randKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// openStores spins up a fresh in-memory SQLite store aggregate for tests.
func openStores(t *testing.T) *store.Stores {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "rpc.db")
	t.Setenv("QUOKKA_MASTER_KEY", randKey(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	stores, err := store.Open(context.Background(), store.Config{DSN: dsn, DataRoot: dir})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	if err := migrations.Up(migrations.DialectSQLite, stores.DB); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return stores
}

// TestRunSidecarDrivesExecutorAndCreatesFindingOverRPC is the new
// end-to-end test for the sidecar: it spins up an in-process RPC
// server, a fake LLM scripted to call finding_create, and asserts
// (a) the executor emits the NDJSON event sequence and (b) a finding
// row lands in the DB through the RPC path.
func TestRunSidecarDrivesExecutorAndCreatesFindingOverRPC(t *testing.T) {
	stores := openStores(t)
	ctx := context.Background()

	// Seed org + repo + run so foreign keys resolve.
	org := &store.Org{Name: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("Orgs.Create: %v", err)
	}
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 1, FullName: "a/b"}
	if err := stores.Repos.Create(ctx, repo); err != nil {
		t.Fatalf("Repos.Create: %v", err)
	}
	run := &store.Run{RepoID: repo.ID, HeadSHA: "head", Status: "queued"}
	if err := stores.Runs.Create(ctx, run); err != nil {
		t.Fatalf("Runs.Create: %v", err)
	}

	// Start the RPC server on net.Pipe.
	serverConn, clientConn := net.Pipe()
	srv := storerpc.NewServer(stores, slog.Default())
	srv.Authenticate("tok", run.ID, org.ID, repo.ID)
	go srv.ServeConnForTest(serverConn)
	t.Cleanup(func() { _ = serverConn.Close(); _ = clientConn.Close() })
	client := storerpc.NewClient(clientConn, "tok")

	// Build a one-agent workflow YAML.
	workflowYAML := `
name: test
version: 1
phases:
  - name: reporting
    mode: sequential
    agents:
      - test-agent
`

	// Build the JobSpec the sidecar will validate.
	spec := jobs.JobSpec{
		SpecVersion:          1,
		RunID:                run.ID,
		RepoID:               repo.ID,
		OrgID:                org.ID,
		HeadSHA:              "head",
		BaseSHA:              "base",
		RepoFullName:         "a/b",
		WorkspaceDir:         "/workspace",
		StateDir:             "/state",
		RPCSocket:            "/var/run/quokka.sock",
		RPCToken:             "tok",
		WorkflowYAML:         workflowYAML,
		DefaultProviderLabel: "default",
		Agents: []jobs.AgentSpec{
			{
				Name: "test-agent",
				Config: agent.AgentConfig{
					Name:           "test-agent",
					Phase:          agent.PhaseReporting,
					ToolsAllowed:   []string{"finding_create"},
					PromptTemplate: "You are test-agent.",
					Applicability:  project.ApplicabilityRule{AlwaysInclude: true},
				},
			},
		},
	}

	// Fake LLM: call finding_create with a known payload, then end_turn.
	findingInput := `{"title":"hardcoded secret","severity":"high","file":"main.go","line_start":5,"description":"oops"}`
	turn1 := []llm.Event{
		{Kind: llm.EventToolCallStart, ToolUseID: "tu1", ToolName: "finding_create"},
		{Kind: llm.EventToolCallDelta, ToolUseID: "tu1", InputDelta: findingInput},
		{Kind: llm.EventToolCallEnd, ToolUseID: "tu1"},
		{Kind: llm.EventStopReason, StopReason: llm.StopToolUse},
	}
	turn2 := []llm.Event{
		{Kind: llm.EventTextDelta, Text: "all done"},
		{Kind: llm.EventStopReason, StopReason: llm.StopEndTurn},
	}
	provider := fake.New("fake", turn1, turn2)
	factory := app.ProviderFactory(func(*agent.ModelConfig) (llm.Provider, error) {
		return provider, nil
	})

	var buf bytes.Buffer
	if err := app.RunSidecar(ctx, &spec, client, factory, &buf); err != nil {
		t.Fatalf("RunSidecar: %v", err)
	}

	// Parse NDJSON lines and assert structure.
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 NDJSON lines (start, tool_call, tool_result, end), got %d:\n%s", len(lines), buf.String())
	}
	kinds := []string{}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad NDJSON line: %v\nline=%q", err, line)
		}
		if m["run_id"] != run.ID {
			t.Errorf("expected run_id=%s, got %v", run.ID, m["run_id"])
		}
		kinds = append(kinds, m["kind"].(string))
	}
	mustContain := []string{"agent_start", "tool_call", "tool_result", "assistant_text"}
	for _, want := range mustContain {
		found := false
		for _, k := range kinds {
			if k == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected kind %q in stream; got kinds=%v", want, kinds)
		}
	}

	// Assert the finding row landed in the DB via RPC.
	findings, err := stores.Findings.ListByRun(ctx, run.ID)
	if err != nil {
		t.Fatalf("Findings.ListByRun: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from RPC tool call, got %d", len(findings))
	}
	got := findings[0]
	if got.Title != "hardcoded secret" || got.Severity != "high" || got.File != "main.go" {
		t.Errorf("finding row contents wrong: %+v", got)
	}
	if got.CreatedBy != "test-agent" {
		t.Errorf("expected created_by=test-agent, got %q", got.CreatedBy)
	}
}
