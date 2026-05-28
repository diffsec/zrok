package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

func TestException_PG_FingerprintAndPattern(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	es := &exceptionStore{db: db}
	// Fingerprint mode
	excFP := &store.ExceptionRow{
		RepoID: repoID, Fingerprint: "fp1",
		Reason: "verified FP", Expires: time.Now().Add(24 * time.Hour),
		ApprovedBy: "alice",
	}
	if err := es.Create(ctx, excFP); err != nil {
		t.Fatalf("create fp: %v", err)
	}
	got, _ := es.Match(ctx, repoID, "fp1", "x.go", "", "")
	if got == nil {
		t.Fatal("expected fp match")
	}

	// Pattern mode (cwe + path glob)
	excPat := &store.ExceptionRow{
		RepoID: repoID, PathGlob: "tests/*.py", CWE: "CWE-89",
		Reason: "tests are exempt", Expires: time.Now().Add(24 * time.Hour),
		ApprovedBy: "alice",
	}
	if err := es.Create(ctx, excPat); err != nil {
		t.Fatalf("create pat: %v", err)
	}
	got, _ = es.Match(ctx, repoID, "other", "tests/sql.py", "CWE-89", "")
	if got == nil {
		t.Fatal("expected path/cwe match")
	}

	// Agent-name mode
	excAgent := &store.ExceptionRow{
		RepoID: repoID, AgentName: "noisy-agent",
		Reason: "muted while tuning", Expires: time.Now().Add(24 * time.Hour),
		ApprovedBy: "alice",
	}
	if err := es.Create(ctx, excAgent); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	got, _ = es.Match(ctx, repoID, "other", "src/x.go", "CWE-1", "noisy-agent")
	if got == nil {
		t.Fatal("expected agent-name match")
	}

	// Validation rejects fingerprint + pattern combo
	err := es.Create(ctx, &store.ExceptionRow{
		RepoID: repoID, Fingerprint: "f", PathGlob: "*",
		Reason: "r", Expires: time.Now().Add(time.Hour), ApprovedBy: "a",
	})
	if err == nil {
		t.Fatal("expected XOR rejection")
	}
}
