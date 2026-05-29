package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

func TestException_FingerprintMode(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	es := &exceptionStore{db: db}
	exc := &store.ExceptionRow{
		RepoID:      repoID,
		Fingerprint: "fp-deadbeef",
		Reason:      "verified false positive after manual audit",
		Expires:     time.Now().Add(90 * 24 * time.Hour),
		ApprovedBy:  "alice",
	}
	if err := es.Create(ctx, exc); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := es.Match(ctx, repoID, "fp-deadbeef", "x.go", "CWE-89", "")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if got == nil || got.ID != exc.ID {
		t.Fatalf("expected match, got %+v", got)
	}
	// Non-matching fingerprint
	got, err = es.Match(ctx, repoID, "different", "x.go", "CWE-89", "")
	if err != nil {
		t.Fatalf("match2: %v", err)
	}
	if got != nil {
		t.Fatalf("expected no match, got %+v", got)
	}
}

func TestException_PatternMode_CWEAndGlob(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	es := &exceptionStore{db: db}
	exc := &store.ExceptionRow{
		RepoID:     repoID,
		PathGlob:   "tests/*.py",
		CWE:        "CWE-89",
		Reason:     "test fixtures are exempt",
		Expires:    time.Now().Add(30 * 24 * time.Hour),
		ApprovedBy: "alice",
	}
	if err := es.Create(ctx, exc); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := es.Match(ctx, repoID, "anyfp", "tests/sql.py", "CWE-89", "")
	if err != nil || got == nil {
		t.Fatalf("expected match path/cwe, got %+v err %v", got, err)
	}
	got, _ = es.Match(ctx, repoID, "anyfp", "src/sql.py", "CWE-89", "")
	if got != nil {
		t.Fatalf("expected NO match outside path, got %+v", got)
	}
	got, _ = es.Match(ctx, repoID, "anyfp", "tests/sql.py", "CWE-79", "")
	if got != nil {
		t.Fatalf("expected NO match different cwe, got %+v", got)
	}
}

func TestException_AgentNameMode(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	es := &exceptionStore{db: db}
	exc := &store.ExceptionRow{
		RepoID:     repoID,
		AgentName:  "noisy-agent",
		Reason:     "agent disabled while we tune it",
		Expires:    time.Now().Add(7 * 24 * time.Hour),
		ApprovedBy: "alice",
	}
	if err := es.Create(ctx, exc); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, _ := es.Match(ctx, repoID, "anyfp", "x.go", "CWE-89", "noisy-agent")
	if got == nil {
		t.Fatal("expected agent-name match")
	}
	got, _ = es.Match(ctx, repoID, "anyfp", "x.go", "CWE-89", "other-agent")
	if got != nil {
		t.Fatalf("expected NO match, got %+v", got)
	}
}

func TestException_Validate_XOR(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	es := &exceptionStore{db: db}
	// Both fingerprint AND pattern is invalid.
	err := es.Create(ctx, &store.ExceptionRow{
		RepoID: repoID, Fingerprint: "fp", PathGlob: "*.py",
		Reason: "r", Expires: time.Now().Add(time.Hour), ApprovedBy: "a",
	})
	if err == nil {
		t.Fatal("expected XOR validation error")
	}
	// Neither: also invalid.
	err = es.Create(ctx, &store.ExceptionRow{
		RepoID: repoID, Reason: "r",
		Expires: time.Now().Add(time.Hour), ApprovedBy: "a",
	})
	if err == nil {
		t.Fatal("expected error for neither fingerprint nor pattern")
	}
}

func TestException_ExpiredNotMatched(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	es := &exceptionStore{db: db}
	if err := es.Create(ctx, &store.ExceptionRow{
		RepoID: repoID, Fingerprint: "fp", Reason: "r",
		Expires: time.Now().Add(-time.Hour), ApprovedBy: "a",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, _ := es.Match(ctx, repoID, "fp", "x", "", "")
	if got != nil {
		t.Fatalf("expected expired exception NOT to match, got %+v", got)
	}
}
