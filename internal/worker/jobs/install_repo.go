package jobs

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/diffsec/quokka/internal/config"
	"github.com/diffsec/quokka/internal/github"
)

// InstallRepo onboards a repository: ensures a row exists, runs a
// best-effort clone of the default branch, and imports any .quokka/ files
// the repo ships into the DB.
//
// In PR-4 we keep this minimal: the row may already exist (the user adds it
// via the UI in PR-5); the clone is optional and skipped when no
// installation token is available.
func InstallRepo(ctx context.Context, deps *Deps, payload []byte) error {
	var p github.InstallRepoPayload
	if err := Decode(payload, &p); err != nil {
		return err
	}
	if deps.Stores == nil {
		return errors.New("InstallRepo: stores not configured")
	}
	repo, err := deps.Stores.Repos.GetByGitHubID(ctx, p.GitHubRepoID)
	if err != nil {
		// PR-5 wires the actual install flow with org context; for PR-4 we
		// log and bail.
		deps.Log.Warn("InstallRepo: repo not found in DB; skipping until UI registration",
			"github_repo_id", p.GitHubRepoID, "full_name", p.RepoFullName)
		return nil
	}
	repo.State = "installing"
	_ = deps.Stores.Repos.Update(ctx, repo)

	if deps.Cloner != nil && deps.GitHub != nil && p.InstallationID != 0 {
		tok, err := deps.GitHub.InstallationToken(ctx, p.InstallationID)
		if err != nil {
			return fmt.Errorf("InstallRepo: install token: %w", err)
		}
		dest := filepath.Join(deps.DataRoot, "repos", repo.ID, "install")
		path, err := deps.Cloner.Clone(ctx, tok, p.RepoFullName, "", 1, dest)
		if err != nil {
			return fmt.Errorf("InstallRepo: clone: %w", err)
		}
		if _, err := config.Import(ctx, deps.Stores, repo.OrgID, repo.ID, path, ""); err != nil {
			deps.Log.Warn("InstallRepo: config import failed", "err", err)
		}
	}

	repo.State = "ready"
	return deps.Stores.Repos.Update(ctx, repo)
}

