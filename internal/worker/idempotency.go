package worker

import "fmt"

// IdempotencyKeyRunPR returns the canonical key for a webhook-driven run. The
// shape is matched by the GitHub webhook handler so a redelivered event
// collides with the original.
func IdempotencyKeyRunPR(repoGitHubID int64, prNumber int, headSHA string) string {
	return fmt.Sprintf("run:%d:%d:%s", repoGitHubID, prNumber, headSHA)
}

// IdempotencyKeyInstall is the per-repo install key.
func IdempotencyKeyInstall(repoGitHubID int64) string {
	return fmt.Sprintf("install:%d", repoGitHubID)
}
