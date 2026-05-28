package vectordb

import (
	"fmt"
	"path/filepath"
	"sync"
)

// VectorStoreRegistry opens HNSW+SQLite metastore pairs lazily per repo_id.
// Each repo's data lives under <dataRoot>/repos/<repo_id>/.
type VectorStoreRegistry struct {
	dataRoot string
	cfgBase  *StoreConfig
	mu       sync.Mutex
	stores   map[string]Store
}

// NewVectorStoreRegistry constructs a registry rooted at dataRoot. cfgBase
// supplies the dimension and HNSW parameters; Path is filled per-repo.
func NewVectorStoreRegistry(dataRoot string, cfgBase *StoreConfig) *VectorStoreRegistry {
	if cfgBase == nil {
		cfgBase = DefaultStoreConfig("", 0)
	}
	return &VectorStoreRegistry{
		dataRoot: dataRoot,
		cfgBase:  cfgBase,
		stores:   make(map[string]Store),
	}
}

// For returns the vector store for repo_id, creating it on first call.
// Cross-repo queries are impossible by construction (no shared backing files).
func (r *VectorStoreRegistry) For(repoID string) (Store, error) {
	if repoID == "" {
		return nil, fmt.Errorf("repoID is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.stores[repoID]; ok {
		return s, nil
	}
	cfg := *r.cfgBase
	cfg.Path = filepath.Join(r.dataRoot, "repos", repoID)
	s, err := NewHNSWStore(&cfg)
	if err != nil {
		return nil, fmt.Errorf("open vector store for repo %s: %w", repoID, err)
	}
	r.stores[repoID] = s
	return s, nil
}

// Close closes every opened store. The first error encountered is returned;
// remaining stores are still closed.
func (r *VectorStoreRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for id, s := range r.stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close %s: %w", id, err)
		}
		delete(r.stores, id)
	}
	return firstErr
}
