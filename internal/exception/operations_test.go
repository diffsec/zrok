package exception_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	migrations "github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/exception"
	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	_ "modernc.org/sqlite"
)

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
	_, _ = stores.DB.ExecContext(ctx, `INSERT INTO organizations(id,name) VALUES('org-1','acme')`)
	_, _ = stores.DB.ExecContext(ctx,
		`INSERT INTO repositories(id,org_id,github_repo_id,full_name,state)
		 VALUES('repo-1','org-1',?,'acme/sample','ready')`, time.Now().UnixNano())
	return stores, "repo-1"
}

func TestException_AddListMatch(t *testing.T) {
	stores, repoID := newTestStores(t)
	ctx := context.Background()

	// Fingerprint mode
	excFP, err := exception.Add(ctx, stores.Exceptions, exception.AddRequest{
		RepoID:      repoID,
		Fingerprint: "fp-abc",
		Reason:      "manually audited",
		Expires:     time.Now().Add(30 * 24 * time.Hour),
		ApprovedBy:  "alice",
	})
	if err != nil {
		t.Fatalf("add fp: %v", err)
	}

	// Pattern mode (cwe + glob)
	_, err = exception.Add(ctx, stores.Exceptions, exception.AddRequest{
		RepoID:     repoID,
		PathGlob:   "tests/*.py",
		CWE:        "CWE-89",
		Reason:     "test fixtures",
		Expires:    time.Now().Add(7 * 24 * time.Hour),
		ApprovedBy: "alice",
	})
	if err != nil {
		t.Fatalf("add pattern: %v", err)
	}

	// Agent-name mode (the new dimension)
	_, err = exception.Add(ctx, stores.Exceptions, exception.AddRequest{
		RepoID:     repoID,
		AgentName:  "noisy-agent",
		Reason:     "muted while tuning",
		Expires:    time.Now().Add(7 * 24 * time.Hour),
		ApprovedBy: "alice",
	})
	if err != nil {
		t.Fatalf("add agent: %v", err)
	}

	list, err := exception.List(ctx, stores.Exceptions, exception.ListRequest{RepoID: repoID})
	if err != nil || len(list) != 3 {
		t.Fatalf("list: %d err %v", len(list), err)
	}

	// Match against the fingerprint exception.
	f := finding.Finding{
		Fingerprint: "fp-abc",
		Location:    finding.Location{File: "src/main.py"},
		CWE:         "CWE-78",
	}
	got, err := exception.Match(ctx, stores.Exceptions, repoID, f)
	if err != nil || got == nil || got.ID != excFP.ID {
		t.Fatalf("expected fp match, got %+v err %v", got, err)
	}

	// Match against the path glob.
	f2 := finding.Finding{
		Fingerprint: "different",
		Location:    finding.Location{File: "tests/sql.py"},
		CWE:         "CWE-89",
	}
	got, _ = exception.Match(ctx, stores.Exceptions, repoID, f2)
	if got == nil {
		t.Fatal("expected path/cwe match")
	}

	// Match by agent name only.
	f3 := finding.Finding{
		Fingerprint: "different",
		Location:    finding.Location{File: "src/anything.go"},
		CWE:         "CWE-1",
		CreatedBy:   "noisy-agent",
	}
	got, _ = exception.Match(ctx, stores.Exceptions, repoID, f3)
	if got == nil {
		t.Fatal("expected agent-name match")
	}

	// Remove
	if err := exception.Remove(ctx, stores.Exceptions, excFP.ID); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, _ = exception.Match(ctx, stores.Exceptions, repoID, f)
	if got != nil {
		t.Fatalf("expected no match after remove, got %+v", got)
	}
}

func TestException_ValidationXOR(t *testing.T) {
	stores, repoID := newTestStores(t)
	ctx := context.Background()
	_, err := exception.Add(ctx, stores.Exceptions, exception.AddRequest{
		RepoID:      repoID,
		Fingerprint: "fp",
		PathGlob:    "*.py",
		Reason:      "r",
		Expires:     time.Now().Add(time.Hour),
		ApprovedBy:  "a",
	})
	if err == nil {
		t.Fatal("expected XOR rejection")
	}
}
