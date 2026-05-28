package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

func seedRepo(t *testing.T, ctx context.Context, db *sql.DB, orgID string) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO repositories(id,org_id,github_repo_id,full_name,state)
		 VALUES($1,$2,$3,$4,$5)`,
		id, orgID, time.Now().UnixNano(), "acme/sample", "ready"); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	return id
}

func TestFinding_PG_CRUDRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	fs := &findingStore{db: db}
	f := &store.FindingRow{
		RepoID:      repoID,
		Fingerprint: "abc123",
		Title:       "SQL injection",
		Severity:    "high",
		Status:      "open",
		CWE:         "CWE-89",
		File:        "src/api.py",
		LineStart:   42,
		Description: "user input concat",
		CreatedBy:   "injection-agent",
		TagsJSON:    `["injection:sql"]`,
	}
	if err := fs.Create(ctx, f); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := fs.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != f.Title || got.CWE != f.CWE {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	got.Status = "fixed"
	if err := fs.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := fs.Delete(ctx, f.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := fs.Get(ctx, f.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFinding_PG_FindByFingerprintAndCreator(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)
	fs := &findingStore{db: db}

	a := &store.FindingRow{
		RepoID: repoID, Fingerprint: "fp", Title: "t", Severity: "high",
		Status: "open", File: "f", LineStart: 1, CreatedBy: "agent-a",
	}
	b := &store.FindingRow{
		RepoID: repoID, Fingerprint: "fp", Title: "t", Severity: "high",
		Status: "open", File: "f", LineStart: 1, CreatedBy: "agent-b",
	}
	if err := fs.Create(ctx, a); err != nil {
		t.Fatalf("a: %v", err)
	}
	if err := fs.Create(ctx, b); err != nil {
		t.Fatalf("b: %v", err)
	}
	got, err := fs.FindByFingerprintAndCreator(ctx, repoID, "fp", "agent-a")
	if err != nil || got.ID != a.ID {
		t.Fatalf("expected a: %+v err %v", got, err)
	}
}

func TestFindingAction_PG_AppendList(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	fs := &findingStore{db: db}
	f := &store.FindingRow{
		RepoID: repoID, Title: "t", Severity: "low", Status: "open",
		File: "f", LineStart: 1, CreatedBy: "agent",
	}
	if err := fs.Create(ctx, f); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	as := &findingActionStore{db: db}
	if err := as.Append(ctx, f.ID, "dismiss", "", "fp", `{}`); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := as.List(ctx, f.ID)
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %d err %v", len(got), err)
	}
}
