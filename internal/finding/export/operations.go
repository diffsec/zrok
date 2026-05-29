package export

import (
	"context"

	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/store"
)

// ExportRequest selects format and (optionally) a repo-scoped subset of
// findings to export. ProjectName is the human-readable name surfaced in
// the rendered output.
type ExportRequest struct {
	RepoID      string
	Format      string
	ProjectName string
	Filter      *finding.ListRequest
}

// Export renders findings for the repo to the requested format and returns
// the encoded bytes. Reuses finding.List so filtering/sort is consistent
// with the list-view code path.
func Export(ctx context.Context, fs store.FindingStore, req ExportRequest) ([]byte, error) {
	filter := finding.ListRequest{RepoID: req.RepoID}
	if req.Filter != nil {
		filter = *req.Filter
		if filter.RepoID == "" {
			filter.RepoID = req.RepoID
		}
	}
	list, err := finding.List(ctx, fs, filter)
	if err != nil {
		return nil, err
	}
	return ExportFindings(list.Findings, req.Format, req.ProjectName)
}
