package memory_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	migrations "github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/memory"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	_ "modernc.org/sqlite"
)

func newTestStores(t *testing.T) (*store.Stores, string) {
	t.Helper()
	t.Setenv("QUOKKA_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "test.db") +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	stores, err := store.Open(context.Background(), store.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	if err := migrations.Up(migrations.DialectSQLite, stores.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	_, _ = stores.DB.ExecContext(ctx, `INSERT INTO organizations(id,name) VALUES('org-1','acme')`)
	_, _ = stores.DB.ExecContext(ctx,
		`INSERT INTO repositories(id,org_id,github_repo_id,full_name,state)
		 VALUES('repo-1','org-1',?,'acme/sample','ready')`, time.Now().UnixNano())
	return stores, "repo-1"
}

func TestMemoryOperations_WriteReadListSearchDelete(t *testing.T) {
	stores, repoID := newTestStores(t)
	ctx := context.Background()

	m, err := memory.Write(ctx, stores.Memories, memory.WriteRequest{
		RepoID:  repoID,
		Name:    "auth-architecture",
		Type:    memory.MemoryTypeContext,
		Content: "session cookies are HMAC-signed",
		Tags:    []string{"auth"},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if m.Name != "auth-architecture" {
		t.Fatalf("write returned wrong memory: %+v", m)
	}
	got, err := memory.Read(ctx, stores.Memories, repoID, "auth-architecture")
	if err != nil || got.Content != m.Content {
		t.Fatalf("read: %+v err %v", got, err)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "auth" {
		t.Fatalf("tags round-trip: %+v", got.Tags)
	}

	list, err := memory.List(ctx, stores.Memories, memory.ListRequest{RepoID: repoID})
	if err != nil || list.Total != 1 {
		t.Fatalf("list: %d err %v", list.Total, err)
	}
	hits, err := memory.Search(ctx, stores.Memories, repoID, "HMAC")
	if err != nil || hits.Total != 1 {
		t.Fatalf("search: %+v err %v", hits, err)
	}
	if err := memory.Delete(ctx, stores.Memories, repoID, "auth-architecture"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := memory.Read(ctx, stores.Memories, repoID, "auth-architecture"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
