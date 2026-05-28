package finding_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	migrations "github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	_ "modernc.org/sqlite"
)

// newTestStores builds a fresh SQLite-backed Stores aggregate with one
// seeded org + repo. Crypto requires a master key; we set a deterministic
// one so the keyring loads cleanly.
func newTestStores(t *testing.T) (*store.Stores, string) {
	t.Helper()
	t.Setenv("QUOKKA_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")

	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "test.db") +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	stores, err := store.Open(context.Background(), store.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	if err := migrations.Up(migrations.DialectSQLite, stores.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	if _, err := stores.DB.ExecContext(ctx,
		`INSERT INTO organizations(id,name) VALUES('org-1','acme')`); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := stores.DB.ExecContext(ctx,
		`INSERT INTO repositories(id,org_id,github_repo_id,full_name,state)
		 VALUES('repo-1','org-1',?,?,'ready')`,
		time.Now().UnixNano(), "acme/sample"); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	return stores, "repo-1"
}

func TestCreate_Dedup(t *testing.T) {
	stores, repoID := newTestStores(t)
	ctx := context.Background()

	req := finding.CreateRequest{
		RepoID:    repoID,
		Title:     "SQL injection in users",
		Severity:  finding.SeverityHigh,
		CWE:       "CWE-89",
		Location:  finding.Location{File: "src/api.py", LineStart: 42},
		CreatedBy: "injection-agent",
	}
	r1, err := finding.Create(ctx, stores.Findings, req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if r1.Deduped {
		t.Fatal("first call should not dedup")
	}
	r2, err := finding.Create(ctx, stores.Findings, req)
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if !r2.Deduped {
		t.Fatal("second call should dedup")
	}
	if r2.Finding.ID != r1.Finding.ID {
		t.Fatalf("dedup returned a different ID: %s vs %s", r2.Finding.ID, r1.Finding.ID)
	}

	// Different creator -> no dedup
	req2 := req
	req2.CreatedBy = "ssrf-agent"
	r3, err := finding.Create(ctx, stores.Findings, req2)
	if err != nil {
		t.Fatalf("create alt: %v", err)
	}
	if r3.Deduped {
		t.Fatal("different creator should not dedup")
	}

	// List returns both
	list, err := finding.List(ctx, stores.Findings, finding.ListRequest{RepoID: repoID})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Total != 2 {
		t.Fatalf("expected 2 findings, got %d", list.Total)
	}
}

func TestTriage_Apply(t *testing.T) {
	stores, repoID := newTestStores(t)
	ctx := context.Background()

	r, err := finding.Create(ctx, stores.Findings, finding.CreateRequest{
		RepoID: repoID, Title: "t", Severity: finding.SeverityHigh,
		Location: finding.Location{File: "x.go", LineStart: 1},
		CreatedBy: "agent",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	plan := finding.TriagePlan{
		Version: 1, Author: "validation-agent",
		Decisions: []finding.TriageDecision{{
			FindingID: r.Finding.ID,
			Status:    "false_positive",
			Reason:    "guarded upstream",
		}},
	}
	res, err := finding.Triage(ctx, stores.Findings, plan)
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if res.Applied != 1 || res.Errored != 0 {
		t.Fatalf("expected applied=1 errored=0, got %+v", res)
	}
	got, _ := finding.Show(ctx, stores.Findings, r.Finding.ID)
	if got.Status != finding.StatusFalsePositive {
		t.Fatalf("status not updated: %q", got.Status)
	}
	if len(got.Notes) != 1 || got.Notes[0].Text != "guarded upstream" {
		t.Fatalf("note not appended: %+v", got.Notes)
	}
}
