// Package navigate's operations.go is the thin facade Brief B's tool
// registry calls into. The existing Lister/Finder/Reader/SymbolExtractor
// types already do the heavy lifting; these wrappers normalize the
// request/response shape so tools don't need to know about the project.
package navigate

import (
	"github.com/diffsec/quokka/internal/project"
)

// ListRequest is the input to List.
type ListRequest struct {
	Project *project.Project
	Path    string
	Options *ListOptions
}

// List returns the directory listing for the given path.
func List(req ListRequest) (*ListResult, error) {
	l := NewLister(req.Project)
	opts := req.Options
	if opts == nil {
		opts = &ListOptions{MaxDepth: 1}
	}
	return l.List(req.Path, opts)
}

// ReadRequest is the input to Read. If LineStart and LineEnd are both
// zero the full file is returned.
type ReadRequest struct {
	Project   *project.Project
	Path      string
	LineStart int
	LineEnd   int
}

// Read returns the contents of a file (or a line range within it).
func Read(req ReadRequest) (*ReadResult, error) {
	r := NewReader(req.Project)
	if req.LineStart > 0 || req.LineEnd > 0 {
		return r.ReadLines(req.Path, req.LineStart, req.LineEnd)
	}
	return r.Read(req.Path)
}

// FindRequest is the input to Find.
type FindRequest struct {
	Project *project.Project
	Pattern string
	Options *FindOptions
}

// Find walks the project and returns the entries matching the glob.
func Find(req FindRequest) (*FindResult, error) {
	f := NewFinder(req.Project)
	return f.Find(req.Pattern, req.Options)
}

// SearchRequest is the input to Search.
type SearchRequest struct {
	Project *project.Project
	Pattern string
	Options *SearchOptions
}

// Search runs a literal-or-regex search across project files.
func Search(req SearchRequest) (*SearchResult, error) {
	f := NewFinder(req.Project)
	return f.Search(req.Pattern, req.Options)
}

// SymbolsRequest is the input to Symbols. Either Path or Name must be set:
// Path extracts all symbols in a file; Name searches across the project.
type SymbolsRequest struct {
	Project *project.Project
	Path    string
	Name    string
}

// Symbols extracts or finds code symbols.
func Symbols(req SymbolsRequest) (*SymbolResult, error) {
	s := NewSymbolExtractor(req.Project)
	if req.Name != "" {
		return s.Find(req.Name)
	}
	return s.Extract(req.Path)
}
