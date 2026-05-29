// Package handlers contains the HTTP request handlers for the web surface.
package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHubUser is the trimmed shape we consume from GET /user.
type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// GitHubEmail is one entry in GET /user/emails.
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// GitHubOrgMembership is one entry in GET /user/orgs.
type GitHubOrgMembership struct {
	Login string `json:"login"`
}

// GitHubOAuthToken is the body returned by POST /login/oauth/access_token.
type GitHubOAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// GitHubClient is the narrow surface the OAuth handler needs. Brief states
// PR-4 will consolidate the real GitHub package; this shim is OAuth-only.
type GitHubClient interface {
	ExchangeCode(ctx context.Context, code string) (*GitHubOAuthToken, error)
	GetUser(ctx context.Context, accessToken string) (*GitHubUser, error)
	GetUserEmails(ctx context.Context, accessToken string) ([]GitHubEmail, error)
	GetUserOrgs(ctx context.Context, accessToken string) ([]GitHubOrgMembership, error)
}

// httpGitHubClient is the real implementation backed by net/http.
type httpGitHubClient struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
	baseURL      string // override for tests; defaults to https://api.github.com
	oauthURL     string // override for tests; defaults to https://github.com/login/oauth/access_token
}

// NewHTTPGitHubClient returns a real-network GitHub client. The two endpoint
// overrides default to GitHub.com when empty.
func NewHTTPGitHubClient(clientID, clientSecret, apiBaseURL, oauthURL string) GitHubClient {
	if apiBaseURL == "" {
		apiBaseURL = "https://api.github.com"
	}
	if oauthURL == "" {
		oauthURL = "https://github.com/login/oauth/access_token"
	}
	return &httpGitHubClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 15 * time.Second},
		baseURL:      strings.TrimRight(apiBaseURL, "/"),
		oauthURL:     oauthURL,
	}
}

func (c *httpGitHubClient) ExchangeCode(ctx context.Context, code string) (*GitHubOAuthToken, error) {
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"code":          {code},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github oauth exchange: %s: %s", resp.Status, string(body))
	}
	var tok GitHubOAuthToken
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("github oauth response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("github oauth response: empty access_token: %s", string(body))
	}
	return &tok, nil
}

func (c *httpGitHubClient) GetUser(ctx context.Context, accessToken string) (*GitHubUser, error) {
	var u GitHubUser
	if err := c.do(ctx, accessToken, "/user", &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (c *httpGitHubClient) GetUserEmails(ctx context.Context, accessToken string) ([]GitHubEmail, error) {
	var out []GitHubEmail
	if err := c.do(ctx, accessToken, "/user/emails", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *httpGitHubClient) GetUserOrgs(ctx context.Context, accessToken string) ([]GitHubOrgMembership, error) {
	var out []GitHubOrgMembership
	if err := c.do(ctx, accessToken, "/user/orgs", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *httpGitHubClient) do(ctx context.Context, token, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("github %s: %s: %s", path, resp.Status, string(body))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}
