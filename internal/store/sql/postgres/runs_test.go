package postgres

import (
	"context"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestRun_CreateListGetUpdate(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	rs := &repoStore{db: db}
	repo := &store.Repository{OrgID: orgID, GitHubRepoID: 1, FullName: "acme/api", State: "ready"}
	if err := rs.Create(ctx, repo); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	runStr := &runStore{db: db}
	r1 := &store.Run{RepoID: repo.ID, Trigger: "manual", Status: "queued"}
	if err := runStr.Create(ctx, r1); err != nil {
		t.Fatalf("run create r1: %v", err)
	}
	r2 := &store.Run{RepoID: repo.ID, Trigger: "pull_request", PRNumber: 7, Status: "queued"}
	if err := runStr.Create(ctx, r2); err != nil {
		t.Fatalf("run create r2: %v", err)
	}

	list, err := runStr.List(ctx, repo.ID, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(list))
	}
	if list[0].ID != r2.ID {
		t.Fatalf("ordering mismatch")
	}

	if err := runStr.UpdateStatus(ctx, r1.ID, "completed"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, err := runStr.Get(ctx, r1.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "completed" {
		t.Fatalf("status mismatch: %q", got.Status)
	}
}
