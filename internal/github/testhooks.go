package github

import "time"

// SeedInstallationToken populates the AppAuth's cache without an HTTP call.
// Intended for tests that exercise consumers of InstallationToken.
func SeedInstallationToken(a *AppAuth, installationID int64, token string, expires time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tokens == nil {
		a.tokens = map[int64]*installationToken{}
	}
	a.tokens[installationID] = &installationToken{Token: token, ExpiresAt: expires}
}
