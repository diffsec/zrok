package storerpc_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	"github.com/diffsec/quokka/internal/storerpc"
)

func randKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// openStores spins up a fresh in-memory SQLite store aggregate for tests.
func openStores(t *testing.T) *store.Stores {
	t.Helper()
	dir := t.TempDir()
	dsn := "sqlite://" + filepath.Join(dir, "rpc.db")
	t.Setenv("QUOKKA_MASTER_KEY", randKey(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	stores, err := store.Open(context.Background(), store.Config{DSN: dsn, DataRoot: dir})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	if err := migrations.Up(migrations.DialectSQLite, stores.DB); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return stores
}

// startServerOnPipe pairs the server with a net.Pipe and returns a
// connected Client. Used by tests that don't want to write to disk.
func startServerOnPipe(t *testing.T, stores *store.Stores, token, runID, orgID, repoID string) *storerpc.Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	srv := storerpc.NewServer(stores, slog.Default())
	srv.Authenticate(token, runID, orgID, repoID)

	// Drive the server side off the pipe directly.
	go func() {
		// We can't use Serve(l) since net.Pipe has no Listener. Use the
		// exported test seam ServeConnForTest.
		srv.ServeConnForTest(serverConn)
	}()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	return storerpc.NewClient(clientConn, token)
}

func TestFindingRoundTrip(t *testing.T) {
	stores := openStores(t)
	ctx := context.Background()

	// Seed an org + repo so the row references resolve.
	org := &store.Org{Name: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("Orgs.Create: %v", err)
	}
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 1, FullName: "a/b"}
	if err := stores.Repos.Create(ctx, repo); err != nil {
		t.Fatalf("Repos.Create: %v", err)
	}
	run := &store.Run{RepoID: repo.ID, HeadSHA: "head-sha", Status: "queued"}
	if err := stores.Runs.Create(ctx, run); err != nil {
		t.Fatalf("Runs.Create: %v", err)
	}

	cli := startServerOnPipe(t, stores, "tok", run.ID, org.ID, repo.ID)

	// Create a finding via RPC.
	row := store.FindingRow{
		RepoID:      repo.ID,
		RunID:       run.ID,
		Fingerprint: "fp-1",
		Title:       "SQL injection",
		Severity:    "high",
		File:        "main.go",
		LineStart:   42,
		CreatedBy:   "security-agent",
	}
	fc := cli.Findings()
	if err := fc.Create(ctx, &row); err != nil {
		t.Fatalf("Create over RPC: %v", err)
	}
	if row.ID == "" {
		t.Fatalf("expected row.ID to be assigned by store, got empty")
	}

	// Verify the DB row matches.
	got, err := stores.Findings.Get(ctx, row.ID)
	if err != nil {
		t.Fatalf("stores.Findings.Get: %v", err)
	}
	if got.Title != "SQL injection" || got.Severity != "high" {
		t.Errorf("DB row mismatch: %+v", got)
	}

	// List via RPC.
	all, err := fc.List(ctx, repo.ID)
	if err != nil {
		t.Fatalf("List over RPC: %v", err)
	}
	if len(all) != 1 || all[0].ID != row.ID {
		t.Errorf("List returned wrong set: %+v", all)
	}
}

func TestRejectsBadToken(t *testing.T) {
	stores := openStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 2, FullName: "a/b2"}
	_ = stores.Repos.Create(ctx, repo)

	// Server is authenticated with token "good"; client uses "bad".
	serverConn, clientConn := net.Pipe()
	srv := storerpc.NewServer(stores, slog.Default())
	srv.Authenticate("good", "run-1", org.ID, repo.ID)
	go srv.ServeConnForTest(serverConn)
	t.Cleanup(func() { _ = serverConn.Close(); _ = clientConn.Close() })

	cli := storerpc.NewClient(clientConn, "bad")
	_, err := cli.Findings().List(ctx, repo.ID)
	if err == nil {
		t.Fatalf("expected unauthorized error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("expected invalid-token error, got %v", err)
	}
}

func TestRejectsOutOfScopeRepo(t *testing.T) {
	stores := openStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repoA := &store.Repository{OrgID: org.ID, GitHubRepoID: 10, FullName: "a/ra"}
	_ = stores.Repos.Create(ctx, repoA)
	repoB := &store.Repository{OrgID: org.ID, GitHubRepoID: 11, FullName: "a/rb"}
	_ = stores.Repos.Create(ctx, repoB)

	cli := startServerOnPipe(t, stores, "tok", "run-1", org.ID, repoA.ID)

	// Try to List findings for repoB — should be rejected.
	_, err := cli.Findings().List(ctx, repoB.ID)
	if err == nil {
		t.Fatalf("expected scope mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "scope mismatch") {
		t.Errorf("expected scope mismatch error, got %v", err)
	}
}

func TestRejectsDisallowedMethod(t *testing.T) {
	// Send a hand-crafted envelope referencing a non-allowlisted method
	// (Providers.Get) and assert the server returns method_not_found.
	stores := openStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 99, FullName: "a/b"}
	_ = stores.Repos.Create(ctx, repo)

	cli := startServerOnPipe(t, stores, "tok", "run-1", org.ID, repo.ID)

	err := cli.CallRawForTest(ctx, "Providers.Get", json.RawMessage(`{"id":"x"}`), nil)
	if err == nil {
		t.Fatalf("expected method-not-allowed error, got nil")
	}
	if !strings.Contains(err.Error(), "method not allowed") {
		t.Errorf("want method not allowed, got %v", err)
	}
}

func TestMemoryRoundTrip(t *testing.T) {
	stores := openStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 5, FullName: "a/c"}
	_ = stores.Repos.Create(ctx, repo)

	cli := startServerOnPipe(t, stores, "tok", "run-1", org.ID, repo.ID)
	mc := cli.Memories()

	row := store.MemoryRow{
		RepoID:    repo.ID,
		Name:      "project_overview",
		Type:      "context",
		Content:   "hello",
		CreatedBy: "recon-agent",
	}
	if err := mc.Upsert(ctx, &row); err != nil {
		t.Fatalf("memory upsert: %v", err)
	}
	got, err := mc.Get(ctx, repo.ID, "project_overview")
	if err != nil {
		t.Fatalf("memory get: %v", err)
	}
	if got.Content != "hello" {
		t.Errorf("unexpected memory content: %+v", got)
	}
}

func TestNotFoundPreservedAcrossRPC(t *testing.T) {
	stores := openStores(t)
	ctx := context.Background()
	org := &store.Org{Name: "acme"}
	_ = stores.Orgs.Create(ctx, org)
	repo := &store.Repository{OrgID: org.ID, GitHubRepoID: 7, FullName: "a/d"}
	_ = stores.Repos.Create(ctx, repo)

	cli := startServerOnPipe(t, stores, "tok", "run-1", org.ID, repo.ID)

	_, err := cli.Findings().Get(ctx, "does-not-exist")
	if err == nil {
		t.Fatalf("expected ErrNotFound, got nil")
	}
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected errors.Is ErrNotFound, got %v", err)
	}
}
