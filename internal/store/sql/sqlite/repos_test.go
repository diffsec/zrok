package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestRepo_CreateListGet(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	rs := &repoStore{db: db}

	r := &store.Repository{
		OrgID:         orgID,
		GitHubRepoID:  42,
		FullName:      "acme/api",
		DefaultBranch: "main",
		Private:       true,
		State:         "ready",
	}
	if err := rs.Create(ctx, r); err != nil {
		t.Fatalf("create: %v", err)
	}
	if r.ID == "" {
		t.Fatal("expected ID assigned")
	}

	got, err := rs.Get(ctx, r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.FullName != "acme/api" || got.State != "ready" || !got.Private {
		t.Fatalf("get mismatch: %+v", got)
	}

	got2, err := rs.GetByGitHubID(ctx, 42)
	if err != nil {
		t.Fatalf("get by gh id: %v", err)
	}
	if got2.ID != r.ID {
		t.Fatalf("gh id mismatch: %s vs %s", got2.ID, r.ID)
	}

	got3, err := rs.GetByFullName(ctx, orgID, "acme/api")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got3.ID != r.ID {
		t.Fatalf("by name mismatch")
	}

	list, err := rs.List(ctx, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list expected 1 got %d", len(list))
	}

	if _, err := rs.GetByGitHubID(ctx, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
