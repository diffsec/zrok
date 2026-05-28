package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/diffsec/quokka/internal/store"
)

func TestMemory_UpsertGetListDelete(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)
	repoID := seedRepo(t, ctx, db, orgID)

	ms := &memoryStore{db: db}
	m := &store.MemoryRow{
		RepoID:      repoID,
		Name:        "auth-architecture",
		Type:        "context",
		Content:     "session cookies are HMAC-signed",
		Description: "auth model overview",
		TagsJSON:    `["auth"]`,
		CreatedBy:   "context-agent",
	}
	if err := ms.Upsert(ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if m.ID == "" {
		t.Fatal("expected ID")
	}

	got, err := ms.Get(ctx, repoID, "auth-architecture")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Content != m.Content || got.Type != "context" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Upsert updates in place.
	m.Content = "HMAC-signed, 30d sliding"
	if err := ms.Upsert(ctx, m); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	got, _ = ms.Get(ctx, repoID, "auth-architecture")
	if got.Content != "HMAC-signed, 30d sliding" {
		t.Fatalf("expected updated content, got %q", got.Content)
	}

	// List
	if err := ms.Upsert(ctx, &store.MemoryRow{
		RepoID: repoID, Name: "patterns-a", Type: "pattern", Content: "regex",
	}); err != nil {
		t.Fatalf("upsert pattern: %v", err)
	}
	all, err := ms.List(ctx, repoID, "")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 memories, got %d", len(all))
	}
	ctxList, err := ms.List(ctx, repoID, "context")
	if err != nil || len(ctxList) != 1 {
		t.Fatalf("filtered list: %d err %v", len(ctxList), err)
	}

	// Search hits content
	hits, err := ms.Search(ctx, repoID, "HMAC")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 || hits[0].Name != "auth-architecture" {
		t.Fatalf("search miss: %+v", hits)
	}

	if err := ms.Delete(ctx, repoID, "auth-architecture"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ms.Get(ctx, repoID, "auth-architecture"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
