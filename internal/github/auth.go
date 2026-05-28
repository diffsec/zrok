// Package github consolidates the GitHub App layer: JWT signing for App-level
// API calls, installation-token caching, webhook dispatch, shallow clone via
// go-git, diff parsing for position-mapping, and the three PR feedback
// writers (Check Run, Review with inline comments, Summary comment).
//
// PR-3's internal/web/handlers/github_client.go is the OAuth-only shim and
// remains usable for the user OAuth flow; this package owns everything else.
package github

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	gogithub "github.com/google/go-github/v66/github"
)

// AppAuth signs App-level JWTs with the GitHub App private key and caches
// installation access tokens.
//
// AppID and a PEM-encoded RSA private key are required (GitHub Apps use
// RSA-SHA256). The private key path is read on first use.
type AppAuth struct {
	AppID          int64
	PrivateKeyPath string

	// Now is overridable for tests.
	Now func() time.Time
	// HTTPClient is the transport used for /app/installations/* requests.
	HTTPClient *http.Client
	// APIBaseURL overrides https://api.github.com for tests.
	APIBaseURL string

	mu       sync.Mutex
	parsedPK crypto.Signer
	tokens   map[int64]*installationToken
}

type installationToken struct {
	Token     string
	ExpiresAt time.Time
}

// NewAppAuth constructs an AppAuth with defaults filled in.
func NewAppAuth(appID int64, privateKeyPath string) *AppAuth {
	return &AppAuth{
		AppID:          appID,
		PrivateKeyPath: privateKeyPath,
		Now:            time.Now,
		HTTPClient:     &http.Client{Timeout: 15 * time.Second},
		APIBaseURL:     "https://api.github.com",
		tokens:         map[int64]*installationToken{},
	}
}

// MintAppJWT returns a freshly-signed App-level JWT, valid for 10 minutes per
// GitHub's spec. Per-call signing is fine; the parsed key is cached.
func (a *AppAuth) MintAppJWT() (string, error) {
	if err := a.loadKey(); err != nil {
		return "", err
	}
	now := a.now().Add(-30 * time.Second) // small drift allowance
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": fmt.Sprintf("%d", a.AppID),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	a.mu.Lock()
	key := a.parsedPK
	a.mu.Unlock()
	return t.SignedString(key)
}

// InstallationToken returns a valid installation access token for the given
// installation ID, minting a new one when none is cached or the cached one
// expires within 5 minutes.
func (a *AppAuth) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	a.mu.Lock()
	tok := a.tokens[installationID]
	a.mu.Unlock()
	if tok != nil && a.now().Add(5*time.Minute).Before(tok.ExpiresAt) {
		return tok.Token, nil
	}
	jwt, err := a.MintAppJWT()
	if err != nil {
		return "", err
	}
	tc := &http.Client{Transport: &bearerTransport{token: jwt, base: a.HTTPClient.Transport}}
	tc.Timeout = a.HTTPClient.Timeout

	client := gogithub.NewClient(tc)
	if a.APIBaseURL != "" && a.APIBaseURL != "https://api.github.com" {
		c, err := client.WithEnterpriseURLs(a.APIBaseURL, a.APIBaseURL)
		if err == nil {
			client = c
		}
	}
	t, _, err := client.Apps.CreateInstallationToken(ctx, installationID, nil)
	if err != nil {
		return "", fmt.Errorf("create installation token: %w", err)
	}
	if t == nil || t.Token == nil {
		return "", errors.New("create installation token: empty response")
	}
	exp := a.now().Add(45 * time.Minute)
	if t.ExpiresAt != nil {
		exp = t.ExpiresAt.Time
	}
	a.mu.Lock()
	a.tokens[installationID] = &installationToken{Token: *t.Token, ExpiresAt: exp}
	a.mu.Unlock()
	return *t.Token, nil
}

// InstallationClient returns a go-github client authenticated as the given
// installation, ready to call /repos/* endpoints.
func (a *AppAuth) InstallationClient(ctx context.Context, installationID int64) (*gogithub.Client, error) {
	tok, err := a.InstallationToken(ctx, installationID)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Transport: &bearerTransport{token: tok, base: a.HTTPClient.Transport}}
	hc.Timeout = a.HTTPClient.Timeout
	client := gogithub.NewClient(hc)
	if a.APIBaseURL != "" && a.APIBaseURL != "https://api.github.com" {
		c, err := client.WithEnterpriseURLs(a.APIBaseURL, a.APIBaseURL)
		if err == nil {
			client = c
		}
	}
	return client, nil
}

func (a *AppAuth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// loadKey reads and parses the App private key once, then caches it.
func (a *AppAuth) loadKey() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.parsedPK != nil {
		return nil
	}
	if a.PrivateKeyPath == "" {
		return errors.New("github: app private key path not set")
	}
	pemBytes, err := os.ReadFile(a.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("read app key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("app key: not PEM-encoded")
	}
	// GitHub Apps use RSA private keys.
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse RSA PKCS1: %w", err)
		}
		a.parsedPK = k
		return nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse PKCS8: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return errors.New("app key: not a signer")
		}
		a.parsedPK = signer
		return nil
	default:
		return fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// bearerTransport is a thin wrapper that adds the Bearer header.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+b.token)
	req2.Header.Set("Accept", "application/vnd.github+json")
	req2.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	t := b.base
	if t == nil {
		t = http.DefaultTransport
	}
	return t.RoundTrip(req2)
}
