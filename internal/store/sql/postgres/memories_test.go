package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestMemory_PG_UpsertGetListSearch(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	ms := &memoryStore{db: db}
	m := &store.MemoryRow{
		RepoID:      repoID,
		Name:        "auth-architecture",
		Type:        "context",
		Content:     "session cookies are HMAC-signed",
		Description: "auth model",
		TagsJSON:    `["auth"]`,
	}
	if err := ms.Upsert(ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := ms.Get(ctx, repoID, "auth-architecture")
	if err != nil || got.Content != m.Content {
		t.Fatalf("get: %+v err %v", got, err)
	}

	// Upsert update path
	m.Content = "rotated to JWT"
	if err := ms.Upsert(ctx, m); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	got, _ = ms.Get(ctx, repoID, "auth-architecture")
	if got.Content != "rotated to JWT" {
		t.Fatalf("expected rotated content, got %q", got.Content)
	}

	hits, err := ms.Search(ctx, repoID, "JWT")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 search hit, got %d", len(hits))
	}

	if err := ms.Delete(ctx, repoID, "auth-architecture"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ms.Get(ctx, repoID, "auth-architecture"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
