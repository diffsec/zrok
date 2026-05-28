package github

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// Cloner is the narrow surface the worker uses to fetch a repo at a PR head
// SHA. It exists as an interface so the job tests can fake it without
// hitting the network.
type Cloner interface {
	Clone(ctx context.Context, installToken, repoFullName, ref string, depth int, destDir string) (string, error)
}

// GoGitCloner is the production go-git impl.
type GoGitCloner struct{}

// Clone performs a shallow git fetch of repoFullName at ref into destDir.
// Returns the on-disk path of the working tree (== destDir). If destDir is
// non-empty it is wiped first.
func (g *GoGitCloner) Clone(ctx context.Context, installToken, repoFullName, ref string, depth int, destDir string) (string, error) {
	if depth <= 0 {
		depth = 50
	}
	if destDir == "" {
		return "", fmt.Errorf("clone: destDir required")
	}
	if err := os.RemoveAll(destDir); err != nil {
		return "", fmt.Errorf("clone: clean %s: %w", destDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
		return "", fmt.Errorf("clone: mkdir parent: %w", err)
	}
	url := fmt.Sprintf("https://github.com/%s.git", repoFullName)
	auth := &githttp.BasicAuth{Username: "x-access-token", Password: installToken}
	opts := &gogit.CloneOptions{
		URL:          url,
		Auth:         auth,
		Depth:        depth,
		SingleBranch: true,
		NoCheckout:   false,
	}
	if ref != "" {
		opts.ReferenceName = plumbing.NewBranchReferenceName(ref)
	}
	repo, err := gogit.PlainCloneContext(ctx, destDir, false, opts)
	if err != nil {
		// Retry with the SHA as a reference for cases where the ref isn't a
		// branch name (PR head SHAs aren't pushed as branches but the API
		// allows fetching by sha via refs/pull/<n>/head). Fall back to a
		// generic clone-then-checkout.
		fallback := &gogit.CloneOptions{
			URL:   url,
			Auth:  auth,
			Depth: depth,
		}
		repo, err = gogit.PlainCloneContext(ctx, destDir, false, fallback)
		if err != nil {
			return "", fmt.Errorf("clone %s: %w", repoFullName, err)
		}
		// If ref looks like a sha, try to checkout.
		if ref != "" && len(ref) >= 7 {
			wt, werr := repo.Worktree()
			if werr == nil {
				_ = wt.Checkout(&gogit.CheckoutOptions{Hash: plumbing.NewHash(ref)})
			}
		}
	}
	return destDir, nil
}

// MaxClone returns the depth to fetch, biased upward so merge-base
// resolution works against the PR base.
func MaxClone(commits int) int {
	if commits+10 > 50 {
		return commits + 10
	}
	return 50
}
