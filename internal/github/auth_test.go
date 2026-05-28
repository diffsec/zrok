package github_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/diffsec/quokka/internal/github"
	"github.com/golang-jwt/jwt/v5"
)

func generateTestKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func TestMintAppJWTContainsExpectedClaims(t *testing.T) {
	path := generateTestKey(t)
	a := github.NewAppAuth(12345, path)
	a.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	tok, err := a.MintAppJWT()
	if err != nil {
		t.Fatalf("MintAppJWT: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "12345" {
		t.Fatalf("iss=%v want 12345", claims["iss"])
	}
	// iat and exp should be present and exp = iat + 10m.
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp-iat < 9*60 || exp-iat > 11*60 {
		t.Fatalf("exp-iat=%v outside ~10min window", exp-iat)
	}
}

func TestInstallationTokenCacheReuse(t *testing.T) {
	path := generateTestKey(t)
	a := github.NewAppAuth(42, path)
	// Seed the cache without going over the network.
	github.SeedInstallationToken(a, 99, "ghs_cached", time.Now().Add(time.Hour))
	tok, err := a.InstallationToken(t.Context(), 99)
	if err != nil {
		t.Fatalf("InstallationToken: %v", err)
	}
	if tok != "ghs_cached" {
		t.Fatalf("expected cached token, got %q", tok)
	}
}
