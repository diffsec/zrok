package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	migrations "github.com/diffsec/quokka/db/migrations"
	cryptopkg "github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db") +
		"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := migrations.Up(migrations.DialectSQLite, db); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return db
}

func randB64Key(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func seedOrg(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	s := &orgStore{db: db}
	o := &store.Org{Name: "acme"}
	if err := s.Create(ctx, o); err != nil {
		t.Fatalf("create org: %v", err)
	}
	return o.ID
}

func TestProvider_CreateGetRoundTrip(t *testing.T) {
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	kr, err := cryptopkg.LoadKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	cipher := cryptopkg.NewCipher(kr)

	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()

	orgID := seedOrg(t, ctx, db)
	ps := &providerStore{db: db, cipher: cipher}

	p := &store.Provider{
		OrgID:    orgID,
		Name:     "anthropic-default",
		Protocol: "anthropic",
		BaseURL:  "https://api.anthropic.com",
		Preset:   "anthropic",
		APIKey:   "sk-fixture",
	}
	if err := ps.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == "" {
		t.Fatal("expected ID assigned")
	}

	// Ciphertext must not equal plaintext on disk.
	var ct []byte
	if err := db.QueryRowContext(ctx, `SELECT api_key_enc FROM providers WHERE id=?`, p.ID).Scan(&ct); err != nil {
		t.Fatalf("query: %v", err)
	}
	if string(ct) == "sk-fixture" {
		t.Fatal("api_key stored as plaintext")
	}

	got, err := ps.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.APIKey != "sk-fixture" {
		t.Fatalf("api_key round-trip mismatch: %q", got.APIKey)
	}
	if got.Name != "anthropic-default" {
		t.Fatalf("name mismatch: %q", got.Name)
	}
}

func TestProvider_WrongMasterKeyFails(t *testing.T) {
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	kr, err := cryptopkg.LoadKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	cipher := cryptopkg.NewCipher(kr)

	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)

	ps := &providerStore{db: db, cipher: cipher}
	p := &store.Provider{
		OrgID:    orgID,
		Name:     "p1",
		Protocol: "anthropic",
		BaseURL:  "https://api.anthropic.com",
		APIKey:   "sk-fixture",
	}
	if err := ps.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Build a fresh cipher with a different master key under the same version.
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	kr2, err := cryptopkg.LoadKeyring()
	if err != nil {
		t.Fatalf("keyring2: %v", err)
	}
	ps2 := &providerStore{db: db, cipher: cryptopkg.NewCipher(kr2)}

	_, err = ps2.Get(ctx, p.ID)
	if err == nil {
		t.Fatal("expected decryption error with wrong master key")
	}
	if !errors.Is(err, cryptopkg.ErrTampered) {
		t.Logf("warning: error not wrapping ErrTampered: %v", err)
	}
}

func TestProvider_RotateKeys(t *testing.T) {
	oldKey := randB64Key(t)
	t.Setenv("QUOKKA_MASTER_KEY", oldKey)
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	krOld, err := cryptopkg.LoadKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	cipherOld := cryptopkg.NewCipher(krOld)

	ctx := context.Background()
	db := newTestDB(t)
	defer db.Close()
	orgID := seedOrg(t, ctx, db)

	psOld := &providerStore{db: db, cipher: cipherOld}
	p := &store.Provider{
		OrgID: orgID, Name: "p1", Protocol: "anthropic",
		BaseURL: "https://api.anthropic.com", APIKey: "sk-fixture",
	}
	if err := psOld.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Simulate that this row was written under the legacy key_version (v0).
	if _, err := db.ExecContext(ctx, `UPDATE providers SET key_version=0 WHERE id=?`, p.ID); err != nil {
		t.Fatalf("set legacy version: %v", err)
	}

	// Now rotate the env: current=new, legacy=old.
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", oldKey)
	krNew, err := cryptopkg.LoadKeyring()
	if err != nil {
		t.Fatalf("keyring new: %v", err)
	}
	psNew := &providerStore{db: db, cipher: cryptopkg.NewCipher(krNew)}

	n, err := psNew.RotateKeys(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 rotated row, got %d", n)
	}

	got, err := psNew.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get after rotate: %v", err)
	}
	if got.APIKey != "sk-fixture" {
		t.Fatalf("api_key mismatch after rotate: %q", got.APIKey)
	}
}
