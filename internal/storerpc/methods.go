package storerpc

import (
	"github.com/diffsec/quokka/internal/store"
)

// Method names. Kept in one place so server and client agree.
const (
	MethodFindingsCreate                = "Findings.Create"
	MethodFindingsGet                   = "Findings.Get"
	MethodFindingsList                  = "Findings.List"
	MethodFindingsListByRun             = "Findings.ListByRun"
	MethodFindingsFindByFingerprint     = "Findings.FindByFingerprintAndCreator"
	MethodFindingsUpdate                = "Findings.Update"
	MethodFindingsUpdateStatus          = "Findings.UpdateStatus"
	MethodFindingsAutoResolveMissing    = "Findings.AutoResolveMissing"

	MethodMemoriesUpsert = "Memories.Upsert"
	MethodMemoriesGet    = "Memories.Get"
	MethodMemoriesList   = "Memories.List"
	MethodMemoriesDelete = "Memories.Delete"
	MethodMemoriesSearch = "Memories.Search"

	MethodExceptionsCreate = "Exceptions.Create"
	MethodExceptionsGet    = "Exceptions.Get"
	MethodExceptionsList   = "Exceptions.List"
	MethodExceptionsDelete = "Exceptions.Delete"
	MethodExceptionsMatch  = "Exceptions.Match"
)

// AllowedMethods is the explicit allowlist the server consults before
// dispatch. Any method name not in this set is rejected with
// CodeMethodNotFound. The list is intentionally narrow — host-only
// stores (Providers, OAuth, Sessions, Users, Runs, ...) are never
// reachable from the sidecar.
var AllowedMethods = map[string]bool{
	MethodFindingsCreate:             true,
	MethodFindingsGet:                true,
	MethodFindingsList:               true,
	MethodFindingsListByRun:          true,
	MethodFindingsFindByFingerprint:  true,
	MethodFindingsUpdate:             true,
	MethodFindingsUpdateStatus:       true,
	MethodFindingsAutoResolveMissing: true,

	MethodMemoriesUpsert: true,
	MethodMemoriesGet:    true,
	MethodMemoriesList:   true,
	MethodMemoriesDelete: true,
	MethodMemoriesSearch: true,

	MethodExceptionsCreate: true,
	MethodExceptionsGet:    true,
	MethodExceptionsList:   true,
	MethodExceptionsDelete: true,
	MethodExceptionsMatch:  true,
}

// --- Findings ---

// FindingsCreateReq wraps a single FindingRow create.
type FindingsCreateReq struct {
	Row store.FindingRow `json:"row"`
}

// FindingsCreateRes returns the persisted row (with assigned ID).
type FindingsCreateRes struct {
	Row store.FindingRow `json:"row"`
}

// FindingsGetReq selects a finding by id.
type FindingsGetReq struct {
	ID string `json:"id"`
}

// FindingsGetRes returns the row.
type FindingsGetRes struct {
	Row store.FindingRow `json:"row"`
}

// FindingsListReq filters by repo.
type FindingsListReq struct {
	RepoID string `json:"repo_id"`
}

// FindingsListRes is a list of rows.
type FindingsListRes struct {
	Rows []store.FindingRow `json:"rows"`
}

// FindingsListByRunReq filters by run.
type FindingsListByRunReq struct {
	RunID string `json:"run_id"`
}

// FindingsFindByFingerprintReq is the per-creator dedup probe.
type FindingsFindByFingerprintReq struct {
	RepoID      string `json:"repo_id"`
	Fingerprint string `json:"fingerprint"`
	CreatedBy   string `json:"created_by"`
}

// FindingsUpdateReq updates one row.
type FindingsUpdateReq struct {
	Row store.FindingRow `json:"row"`
}

// FindingsUpdateStatusReq moves a single row's status.
type FindingsUpdateStatusReq struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// FindingsAutoResolveMissingReq carries the seen-fingerprint set.
type FindingsAutoResolveMissingReq struct {
	RepoID            string   `json:"repo_id"`
	SeenFingerprints  []string `json:"seen_fingerprints"`
}

// FindingsAutoResolveMissingRes returns the resolved-count.
type FindingsAutoResolveMissingRes struct {
	Count int64 `json:"count"`
}

// --- Memories ---

// MemoriesUpsertReq upserts one row.
type MemoriesUpsertReq struct {
	Row store.MemoryRow `json:"row"`
}

// MemoriesUpsertRes returns the persisted row.
type MemoriesUpsertRes struct {
	Row store.MemoryRow `json:"row"`
}

// MemoriesGetReq fetches by (repo, name).
type MemoriesGetReq struct {
	RepoID string `json:"repo_id"`
	Name   string `json:"name"`
}

// MemoriesGetRes returns one row.
type MemoriesGetRes struct {
	Row store.MemoryRow `json:"row"`
}

// MemoriesListReq lists by repo with optional type filter.
type MemoriesListReq struct {
	RepoID string `json:"repo_id"`
	Type   string `json:"type"`
}

// MemoriesListRes returns the row list.
type MemoriesListRes struct {
	Rows []store.MemoryRow `json:"rows"`
}

// MemoriesDeleteReq removes by (repo, name).
type MemoriesDeleteReq struct {
	RepoID string `json:"repo_id"`
	Name   string `json:"name"`
}

// MemoriesSearchReq runs a substring/FTS search.
type MemoriesSearchReq struct {
	RepoID string `json:"repo_id"`
	Query  string `json:"query"`
}

// --- Exceptions ---

// ExceptionsCreateReq creates one row.
type ExceptionsCreateReq struct {
	Row store.ExceptionRow `json:"row"`
}

// ExceptionsCreateRes returns the persisted row.
type ExceptionsCreateRes struct {
	Row store.ExceptionRow `json:"row"`
}

// ExceptionsGetReq fetches by id.
type ExceptionsGetReq struct {
	ID string `json:"id"`
}

// ExceptionsGetRes returns the row.
type ExceptionsGetRes struct {
	Row store.ExceptionRow `json:"row"`
}

// ExceptionsListReq lists by repo.
type ExceptionsListReq struct {
	RepoID string `json:"repo_id"`
}

// ExceptionsListRes returns the row list.
type ExceptionsListRes struct {
	Rows []store.ExceptionRow `json:"rows"`
}

// ExceptionsDeleteReq removes by id.
type ExceptionsDeleteReq struct {
	ID string `json:"id"`
}

// ExceptionsMatchReq probes for a suppression match.
type ExceptionsMatchReq struct {
	RepoID      string `json:"repo_id"`
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	CWE         string `json:"cwe"`
	AgentName   string `json:"agent_name"`
}

// ExceptionsMatchRes returns the matched row (nil when no match).
type ExceptionsMatchRes struct {
	Row *store.ExceptionRow `json:"row"`
}

// EmptyRes is the unit response shape for void-returning methods.
type EmptyRes struct{}

