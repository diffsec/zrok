package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestRepo_CreateListGet(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
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

	got, err := rs.Get(ctx, r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.FullName != "acme/api" {
		t.Fatalf("get mismatch: %+v", got)
	}

	got2, err := rs.GetByGitHubID(ctx, 42)
	if err != nil {
		t.Fatalf("get by gh id: %v", err)
	}
	if got2.ID != r.ID {
		t.Fatalf("id mismatch")
	}

	got3, err := rs.GetByFullName(ctx, orgID, "acme/api")
	if err != nil {
		t.Fatalf("get by name: %v", err)
	}
	if got3.ID != r.ID {
		t.Fatalf("id mismatch by name")
	}

	list, err := rs.List(ctx, orgID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	if _, err := rs.GetByGitHubID(ctx, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound: %v", err)
	}
}
