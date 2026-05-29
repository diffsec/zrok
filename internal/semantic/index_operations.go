package semantic

import (
	"context"

	"github.com/diffsec/quokka/internal/project"
)

// BuildRequest is the input to Build. Force=true triggers a full rebuild.
type BuildRequest struct {
	Project  *project.Project
	Config   *IndexerConfig
	Force    bool
	Progress ProgressCallback
}

// Build runs an initial (or forced) index build for the project.
func Build(ctx context.Context, req BuildRequest) error {
	idx, err := NewIndexer(req.Project, req.Config)
	if err != nil {
		return err
	}
	return idx.Build(ctx, req.Force, req.Progress)
}

// UpdateRequest is the input to Update — an incremental scan of files
// whose content_hash has changed since the last index pass.
type UpdateRequest struct {
	Project  *project.Project
	Config   *IndexerConfig
	Progress ProgressCallback
}

// Update runs an incremental index pass; returns the number of files
// re-indexed.
func Update(ctx context.Context, req UpdateRequest) (int, error) {
	idx, err := NewIndexer(req.Project, req.Config)
	if err != nil {
		return 0, err
	}
	return idx.Update(ctx, req.Progress)
}
