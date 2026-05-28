package sqlite

import (
	"context"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestRun_CreateListGetUpdate(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	rs := &repoStore{db: db}
	repo := &store.Repository{OrgID: orgID, GitHubRepoID: 1, FullName: "acme/api", State: "ready"}
	if err := rs.Create(ctx, repo); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	runStr := &runStore{db: db}
	r1 := &store.Run{RepoID: repo.ID, Trigger: "manual", Status: "queued", HeadSHA: "deadbeef", BaseSHA: "cafef00d"}
	if err := runStr.Create(ctx, r1); err != nil {
		t.Fatalf("run create r1: %v", err)
	}
	r2 := &store.Run{RepoID: repo.ID, Trigger: "pull_request", PRNumber: 7, Status: "queued", HeadSHA: "abc"}
	if err := runStr.Create(ctx, r2); err != nil {
		t.Fatalf("run create r2: %v", err)
	}

	got, err := runStr.Get(ctx, r1.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Trigger != "manual" || got.HeadSHA != "deadbeef" {
		t.Fatalf("get mismatch: %+v", got)
	}

	list, err := runStr.List(ctx, repo.ID, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(list))
	}
	// Most recent first.
	if list[0].ID != r2.ID {
		t.Fatalf("ordering mismatch: %s", list[0].ID)
	}

	if err := runStr.UpdateStatus(ctx, r1.ID, "completed"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got2, err := runStr.Get(ctx, r1.ID)
	if err != nil {
		t.Fatalf("get2: %v", err)
	}
	if got2.Status != "completed" {
		t.Fatalf("status not updated: %q", got2.Status)
	}
}
