package postgres

import (
	"context"
	"errors"
	"testing"

	cryptopkg "github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
)

func newCipher(t *testing.T) *cryptopkg.Cipher {
	t.Helper()
	t.Setenv("QUOKKA_MASTER_KEY", randB64Key(t))
	t.Setenv("QUOKKA_MASTER_KEY_OLD", "")
	kr, err := cryptopkg.LoadKeyring()
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return cryptopkg.NewCipher(kr)
}

func TestOAuth_UpsertGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newPGTestDB(t)
	orgID := seedOrg(t, ctx, db)
	cipher := newCipher(t)

	us := &userStore{db: db}
	u := &store.User{OrgID: orgID, GitHubLogin: "alice", GitHubID: 1, Role: "admin"}
	if err := us.Create(ctx, u); err != nil {
		t.Fatalf("user create: %v", err)
	}

	os := &oauthStore{db: db, cipher: cipher}
	tok := &store.OAuthToken{
		UserID:       u.ID,
		Provider:     "github",
		AccessToken:  "gho_secret",
		RefreshToken: "ghr_secret",
		Scopes:       "read:user",
	}
	if err := os.Upsert(ctx, tok); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := os.Get(ctx, u.ID, "github")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AccessToken != "gho_secret" || got.RefreshToken != "ghr_secret" {
		t.Fatalf("token round-trip mismatch: %+v", got)
	}

	tok.AccessToken = "gho_new"
	tok.RefreshToken = ""
	if err := os.Upsert(ctx, tok); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err = os.Get(ctx, u.ID, "github")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.AccessToken != "gho_new" {
		t.Fatalf("update mismatch: %q", got.AccessToken)
	}

	if err := os.Delete(ctx, u.ID, "github"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Get(ctx, u.ID, "github"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound: %v", err)
	}
}
