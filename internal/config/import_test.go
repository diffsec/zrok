package config_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/config"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
)

func randB64Key(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func openTestStores(t *testing.T) *store.Stores {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "test.db")
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
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

func TestImportLoadsAgentExceptionMemoryFromFixtureRepo(t *testing.T) {
	stores := openTestStores(t)
	ctx := context.Background()

	org := &store.Org{Name: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("Orgs.Create: %v", err)
	}
	repo := &store.Repository{
		OrgID:        org.ID,
		GitHubRepoID: 4242,
		FullName:     "acme/widget",
	}
	if err := stores.Repos.Create(ctx, repo); err != nil {
		t.Fatalf("Repos.Create: %v", err)
	}

	root := t.TempDir()
	mkdir := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	write := func(p, body string) {
		mkdir(filepath.Dir(p))
		if err := os.WriteFile(filepath.Join(root, p), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	write(".quokka/project.yaml", `name: widget
version: "1.0"
detected_at: 2024-01-01T00:00:00Z
tech_stack:
  languages:
    - name: go
classification:
  types: [api-service]
  traits: [has-datastore]
`)
	write(".quokka/agents/foo.yaml", `name: foo
description: test agent
phase: analysis
tools_allowed: [navigate_read]
prompt_template: hello
`)
	write(".quokka/exceptions.yaml", `- id: exc-1
  cwe: CWE-79
  reason: false positive in vendored lib
  expires: 2099-01-01T00:00:00Z
  approved_by: alice
`)
	write(".quokka/memories/architecture.yaml", `name: architecture
type: context
description: layered service
content: |
  Layers: api -> service -> repo
`)

	res, err := config.Import(ctx, stores, org.ID, repo.ID, root, "abc1234")
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !res.ProjectFound {
		t.Fatalf("expected project.yaml to be loaded")
	}
	if len(res.AgentConfigs) != 1 {
		t.Fatalf("expected 1 agent config, got %d", len(res.AgentConfigs))
	}
	if len(res.Exceptions) != 1 {
		t.Fatalf("expected 1 exception, got %d", len(res.Exceptions))
	}
	if len(res.Memories) != 1 {
		t.Fatalf("expected 1 memory, got %d", len(res.Memories))
	}

	ac, err := stores.AgentConfigs.GetByName(ctx, org.ID, "foo")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	revs, err := stores.AgentConfigs.ListRevisions(ctx, ac.ID)
	if err != nil || len(revs) == 0 {
		t.Fatalf("ListRevisions: %v len=%d", err, len(revs))
	}
	if revs[0].ImportSHA != "abc1234" {
		t.Fatalf("expected import_sha=abc1234, got %q", revs[0].ImportSHA)
	}
	if ac.Source != "repo-import" {
		t.Fatalf("expected source=repo-import, got %q", ac.Source)
	}

	repo2, _ := stores.Repos.Get(ctx, repo.ID)
	if repo2.ClassificationJSON == "" {
		t.Fatalf("expected classification_json populated")
	}
}
