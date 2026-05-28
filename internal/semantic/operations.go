// Package semantic's operations.go exposes the search/related calls the
// tool registry uses. The existing Searcher does the work; these wrappers
// normalize the request shape.
package semantic

import (
	"context"

	"github.com/diffsec/quokka/internal/embedding"
	"github.com/diffsec/quokka/internal/vectordb"
)

// SearchRequest is the input to Search.
type SearchRequest struct {
	Store    vectordb.Store
	Provider embedding.Provider
	Query    string
	Options  *SearchOptions
}

// Search runs a natural-language search across the indexed code chunks.
func Search(ctx context.Context, req SearchRequest) (*SearchResults, error) {
	s := NewSearcher(req.Store, req.Provider)
	return s.Search(ctx, req.Query, req.Options)
}

// RelatedRequest is the input to Related — find chunks similar to the
// chunk(s) in the named file.
type RelatedRequest struct {
	Store    vectordb.Store
	Provider embedding.Provider
	File     string
	Options  *SearchOptions
}

// Related returns chunks semantically related to the chunks in the given
// file.
func Related(ctx context.Context, req RelatedRequest) (*SearchResults, error) {
	s := NewSearcher(req.Store, req.Provider)
	return s.SearchByFile(ctx, req.File, req.Options)
}
