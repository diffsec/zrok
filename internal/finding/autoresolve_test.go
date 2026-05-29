package finding_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"testing"

	migrations "github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	_ "modernc.org/sqlite"
)

func newStores(t *testing.T) *store.Stores {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := migrations.Up(migrations.DialectSQLite, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = db.Close()

	keyRaw := make([]byte, 32)
	_, _ = rand.Read(keyRaw)
	t.Setenv("QUOKKA_MASTER_KEY", base64.StdEncoding.EncodeToString(keyRaw))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	if _, err := crypto.LoadKeyring(); err != nil {
		t.Fatalf("keyring: %v", err)
	}
	stores, err := store.Open(context.Background(), store.Config{DSN: "sqlite:///" + path})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	return stores
}

func TestAutoResolve_FlipsMissingFingerprints(t *testing.T) {
	stores := newStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 1, FullName: "acme/x", DefaultBranch: "main", State: "ready"}
	_ = stores.Repos.Create(ctx, repo)

	run1 := &store.Run{RepoID: repo.ID, Trigger: "manual", Status: "completed", HeadSHA: "aaa"}
	_ = stores.Runs.Create(ctx, run1)
	run2 := &store.Run{RepoID: repo.ID, Trigger: "manual", Status: "completed", HeadSHA: "bbb"}
	_ = stores.Runs.Create(ctx, run2)

	// Run N: create finding F1 with fingerprint "fp-1".
	_, err := finding.Create(ctx, stores.Findings, finding.CreateRequest{
		RepoID:    repo.ID,
		RunID:     run1.ID,
		Title:     "sql-i",
		Severity:  finding.SeverityHigh,
		Status:    finding.StatusOpen,
		Location:  finding.Location{File: "main.go", LineStart: 10},
		CreatedBy: "injection-agent",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Auto-resolve with an empty seen set (no findings in the new run) ⇒ F1
	// flips to 'fixed'.
	n, err := stores.Findings.AutoResolveMissing(ctx, repo.ID, nil)
	if err != nil {
		t.Fatalf("auto-resolve: %v", err)
	}
	if n != 1 {
		t.Errorf("auto-resolve count = %d want 1", n)
	}
	// Re-emerge: the same finding shape gets re-emitted by run-2. Per-creator
	// dedup logic in finding.Create now flips it back to 'open' and bumps
	// reopened_count.
	res2, err := finding.Create(ctx, stores.Findings, finding.CreateRequest{
		RepoID:    repo.ID,
		RunID:     run2.ID,
		Title:     "sql-i",
		Severity:  finding.SeverityHigh,
		Status:    finding.StatusOpen,
		Location:  finding.Location{File: "main.go", LineStart: 10},
		CreatedBy: "injection-agent",
	})
	if err != nil {
		t.Fatalf("create re-emerge: %v", err)
	}
	if !res2.Deduped {
		t.Errorf("expected dedup on re-emerge")
	}
	if res2.Finding.Status != finding.StatusOpen {
		t.Errorf("status = %q want open", res2.Finding.Status)
	}
	// The store row should now have reopened_count=1.
	rows, _ := stores.Findings.List(ctx, repo.ID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].ReopenedCount != 1 {
		t.Errorf("reopened_count = %d want 1", rows[0].ReopenedCount)
	}
	if rows[0].Status != "open" {
		t.Errorf("status = %q want open", rows[0].Status)
	}
}
