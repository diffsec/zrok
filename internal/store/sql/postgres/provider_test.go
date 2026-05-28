package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	migrations "github.com/diffsec/quokka/db/migrations"
	cryptopkg "github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func newPGTestDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping testcontainers in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("quokka_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute),
		),
	)
	if err != nil {
		t.Skipf("docker unavailable, skipping postgres test: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Terminate(context.Background())
	})

	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("conn string: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := migrations.Up(migrations.DialectPostgres, db); err != nil {
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

	db := newPGTestDB(t)
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

	got, err := ps.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.APIKey != "sk-fixture" {
		t.Fatalf("api_key round-trip mismatch: %q", got.APIKey)
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

	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	ps := &providerStore{db: db, cipher: cipher}

	p := &store.Provider{
		OrgID: orgID, Name: "p1", Protocol: "anthropic",
		BaseURL: "https://api.anthropic.com", APIKey: "sk-fixture",
	}
	if err := ps.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}

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
