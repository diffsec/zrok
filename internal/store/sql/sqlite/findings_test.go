package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

func seedRepo(t *testing.T, ctx context.Context, db *sql.DB, orgID string) string {
	t.Helper()
	r := &store.Repository{
		OrgID:        orgID,
		GitHubRepoID: time.Now().UnixNano(),
		FullName:     "acme/sample",
		State:        "ready",
	}
	// Insert directly since RepositoryStore is still a stub. Mirrors the
	// shape Brief B will adopt once it lights up the install/repo flow.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO repositories(id,org_id,github_repo_id,full_name,state)
		 VALUES(?,?,?,?,?)`,
		"repo-1", orgID, r.GitHubRepoID, r.FullName, r.State); err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	return "repo-1"
}

func TestFinding_CRUDRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()

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
	if f.ID == "" {
		t.Fatal("expected ID set")
	}

	got, err := fs.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "SQL injection" || got.CWE != "CWE-89" || got.CreatedBy != "injection-agent" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.TagsJSON != `["injection:sql"]` {
		t.Fatalf("tags round-trip mismatch: %q", got.TagsJSON)
	}

	// Update changes status and notes.
	got.Status = "confirmed"
	got.NotesJSON = `[{"text":"verified"}]`
	if err := fs.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := fs.Get(ctx, f.ID)
	if got2.Status != "confirmed" || got2.NotesJSON != `[{"text":"verified"}]` {
		t.Fatalf("update did not persist: %+v", got2)
	}

	// UpdateStatus shortcut.
	if err := fs.UpdateStatus(ctx, f.ID, "fixed"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got3, _ := fs.Get(ctx, f.ID)
	if got3.Status != "fixed" {
		t.Fatalf("status not fixed: %q", got3.Status)
	}

	list, err := fs.List(ctx, repoID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	if err := fs.Delete(ctx, f.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := fs.Get(ctx, f.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestFinding_FindByFingerprintAndCreator(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()

	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)
	fs := &findingStore{db: db}

	mk := func(creator string) *store.FindingRow {
		return &store.FindingRow{
			RepoID:      repoID,
			Fingerprint: "fpA",
			Title:       "Same vuln, two reporters",
			Severity:    "high",
			Status:      "open",
			File:        "x.go",
			LineStart:   1,
			CreatedBy:   creator,
		}
	}
	a := mk("agent-a")
	b := mk("agent-b")
	if err := fs.Create(ctx, a); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := fs.Create(ctx, b); err != nil {
		t.Fatalf("create b (same fp diff creator): %v", err)
	}

	got, err := fs.FindByFingerprintAndCreator(ctx, repoID, "fpA", "agent-a")
	if err != nil || got.ID != a.ID {
		t.Fatalf("expected a, got %+v err %v", got, err)
	}
	got, err = fs.FindByFingerprintAndCreator(ctx, repoID, "fpA", "agent-b")
	if err != nil || got.ID != b.ID {
		t.Fatalf("expected b, got %+v err %v", got, err)
	}
	_, err = fs.FindByFingerprintAndCreator(ctx, repoID, "fpA", "agent-c")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFindingAction_AppendAndList(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	fs := &findingStore{db: db}
	f := &store.FindingRow{
		RepoID: repoID, Title: "t", Severity: "low", Status: "open",
		File: "f", LineStart: 1, CreatedBy: "agent",
	}
	if err := fs.Create(ctx, f); err != nil {
		t.Fatalf("create finding: %v", err)
	}

	as := &findingActionStore{db: db}
	if err := as.Append(ctx, f.ID, "dismiss", "", "false positive", `{}`); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := as.Append(ctx, f.ID, "reopen", "", "", ""); err != nil {
		t.Fatalf("append 2: %v", err)
	}
	got, err := as.List(ctx, f.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(got))
	}
	if got[0].Action != "dismiss" || got[0].Reason != "false positive" {
		t.Fatalf("first action: %+v", got[0])
	}
}
