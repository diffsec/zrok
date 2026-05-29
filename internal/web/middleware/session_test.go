package middleware

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
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

func testStores(t *testing.T) *store.Stores {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	migDB, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	migDB.SetMaxOpenConns(1)
	if err := migrations.Up(migrations.DialectSQLite, migDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migDB.Close()

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

func seedUser(t *testing.T, stores *store.Stores) *store.User {
	t.Helper()
	ctx := context.Background()
	org := &store.Org{Name: "acme", GitHubLogin: "acme"}
	if err := stores.Orgs.Create(ctx, org); err != nil {
		t.Fatalf("org: %v", err)
	}
	u := &store.User{OrgID: org.ID, GitHubID: 99, GitHubLogin: "alice", Role: "admin"}
	if err := stores.Users.Create(ctx, u); err != nil {
		t.Fatalf("user: %v", err)
	}
	return u
}

func TestSession_NoCookie_Anonymous(t *testing.T) {
	stores := testStores(t)
	called := false
	h := Session(stores, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if webctx.UserFromCtx(r.Context()) != nil {
			t.Fatal("expected anonymous context")
		}
		called = true
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !called {
		t.Fatal("handler not called")
	}
}

func TestSession_ValidCookie_AttachesUser(t *testing.T) {
	stores := testStores(t)
	u := seedUser(t, stores)
	ctx := context.Background()
	sess := &store.Session{UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	if err := stores.Sessions.Create(ctx, sess); err != nil {
		t.Fatalf("session: %v", err)
	}
	var seenUser *store.User
	h := Session(stores, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUser = webctx.UserFromCtx(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if seenUser == nil || seenUser.ID != u.ID {
		t.Fatalf("user not attached: %+v", seenUser)
	}
}

func TestSession_ExpiredCookie_Cleared(t *testing.T) {
	stores := testStores(t)
	u := seedUser(t, stores)
	ctx := context.Background()
	sess := &store.Session{UserID: u.ID, ExpiresAt: time.Now().Add(-time.Hour)}
	if err := stores.Sessions.Create(ctx, sess); err != nil {
		t.Fatalf("session: %v", err)
	}
	h := Session(stores, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if webctx.UserFromCtx(r.Context()) != nil {
			t.Fatal("expired session attached user")
		}
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	// Cookie should be cleared.
	var sawClear bool
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			sawClear = true
		}
	}
	if !sawClear {
		t.Fatal("expected session cookie clearance")
	}
}

func TestSession_TouchExtendsExpiry(t *testing.T) {
	stores := testStores(t)
	u := seedUser(t, stores)
	ctx := context.Background()
	old := time.Now().Add(time.Hour).UTC()
	sess := &store.Session{UserID: u.ID, ExpiresAt: old}
	if err := stores.Sessions.Create(ctx, sess); err != nil {
		t.Fatalf("session: %v", err)
	}
	h := Session(stores, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	got, err := stores.Sessions.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if !got.ExpiresAt.After(old) {
		t.Fatalf("expected expires_at to advance: was %v, now %v", old, got.ExpiresAt)
	}
}
