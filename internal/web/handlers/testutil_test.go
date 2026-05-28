package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	migrations "github.com/diffsec/quokka/db/migrations"
	"github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/diffsec/quokka/internal/store/sql/sqlite"
	"github.com/diffsec/quokka/internal/web/webctx"
	_ "modernc.org/sqlite"
)

func newTestStores(t *testing.T) *store.Stores {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	openOnce := func() *sql.DB {
		db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		db.SetMaxOpenConns(1)
		return db
	}
	migrateDB := openOnce()
	if err := migrations.Up(migrations.DialectSQLite, migrateDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrateDB.Close()

	keyRaw := make([]byte, 32)
	_, _ = rand.Read(keyRaw)
	t.Setenv("QUOKKA_MASTER_KEY", base64.StdEncoding.EncodeToString(keyRaw))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	if _, err := crypto.LoadKeyring(); err != nil {
		t.Fatalf("keyring: %v", err)
	}
	stores, err := store.Open(context.Background(), store.Config{DSN: "sqlite:///" + dbPath})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	return stores
}

// fakeGitHub returns canned GitHub responses for testing the OAuth flow.
type fakeGitHub struct {
	exchangeCalled bool
	tok            *GitHubOAuthToken
	user           *GitHubUser
	emails         []GitHubEmail
	orgs           []GitHubOrgMembership
	exchangeErr    error
}

func (f *fakeGitHub) ExchangeCode(ctx context.Context, code string) (*GitHubOAuthToken, error) {
	f.exchangeCalled = true
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
	if f.tok == nil {
		return &GitHubOAuthToken{AccessToken: "fake-access", Scope: "read:user"}, nil
	}
	return f.tok, nil
}
func (f *fakeGitHub) GetUser(ctx context.Context, _ string) (*GitHubUser, error) {
	return f.user, nil
}
func (f *fakeGitHub) GetUserEmails(ctx context.Context, _ string) ([]GitHubEmail, error) {
	return f.emails, nil
}
func (f *fakeGitHub) GetUserOrgs(ctx context.Context, _ string) ([]GitHubOrgMembership, error) {
	return f.orgs, nil
}

func newSeedUser(h *AuthHandler, login string) *store.User {
	return &store.User{
		GitHubID:    int64(len(login)) + 100,
		GitHubLogin: login,
		Role:        "member",
	}
}

func newTestSession(userID string) *store.Session {
	return &store.Session{
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// stubSessionCtx injects a session into a request context without going through
// the Session middleware (which would also touch the store).
func stubSessionCtx(ctx context.Context, sess *store.Session) context.Context {
	return webctx.WithSession(ctx, sess)
}
