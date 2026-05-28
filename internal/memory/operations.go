// Package memory's operations.go exposes the pure-Go business functions
// the SaaS tool registry calls. They take explicit request structs and the
// store.MemoryStore interface.
package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/diffsec/quokka/internal/store"
)

// WriteRequest carries everything needed to persist a memory.
type WriteRequest struct {
	RepoID      string
	Name        string
	Type        MemoryType
	Content     string
	Description string
	Tags        []string
	CreatedBy   string
}

// Write upserts a memory (creates new or updates existing by name).
func Write(ctx context.Context, ms store.MemoryStore, req WriteRequest) (*Memory, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, errors.New("memory name is required")
	}
	if req.Type == "" {
		req.Type = MemoryTypeContext
	}
	if !IsValidType(req.Type) {
		return nil, fmt.Errorf("invalid memory type: %s", req.Type)
	}
	tagsJSON := ""
	if len(req.Tags) > 0 {
		b, err := json.Marshal(req.Tags)
		if err != nil {
			return nil, err
		}
		tagsJSON = string(b)
	}
	row := &store.MemoryRow{
		RepoID:      req.RepoID,
		Name:        req.Name,
		Type:        string(req.Type),
		Content:     req.Content,
		Description: req.Description,
		TagsJSON:    tagsJSON,
		CreatedBy:   req.CreatedBy,
	}
	if err := ms.Upsert(ctx, row); err != nil {
		return nil, err
	}
	return rowToMemory(row), nil
}

// Read fetches a memory by repo + name.
func Read(ctx context.Context, ms store.MemoryStore, repoID, name string) (*Memory, error) {
	row, err := ms.Get(ctx, repoID, name)
	if err != nil {
		return nil, err
	}
	return rowToMemory(row), nil
}

// ListRequest filters a List call. Empty Type lists all types.
type ListRequest struct {
	RepoID string
	Type   MemoryType
}

// List returns repo-scoped memories, optionally filtered by type.
func List(ctx context.Context, ms store.MemoryStore, req ListRequest) (*MemoryList, error) {
	if req.Type != "" && !IsValidType(req.Type) {
		return nil, fmt.Errorf("invalid memory type: %s", req.Type)
	}
	rows, err := ms.List(ctx, req.RepoID, string(req.Type))
	if err != nil {
		return nil, err
	}
	out := make([]Memory, 0, len(rows))
	for _, r := range rows {
		out = append(out, *rowToMemory(r))
	}
	return &MemoryList{Memories: out, Total: len(out), Type: string(req.Type)}, nil
}

// Search runs a substring/FTS search across memories in a repo.
func Search(ctx context.Context, ms store.MemoryStore, repoID, query string) (*MemoryList, error) {
	rows, err := ms.Search(ctx, repoID, query)
	if err != nil {
		return nil, err
	}
	out := make([]Memory, 0, len(rows))
	for _, r := range rows {
		out = append(out, *rowToMemory(r))
	}
	return &MemoryList{Memories: out, Total: len(out)}, nil
}

// Delete removes a memory by repo + name.
func Delete(ctx context.Context, ms store.MemoryStore, repoID, name string) error {
	return ms.Delete(ctx, repoID, name)
}

func rowToMemory(row *store.MemoryRow) *Memory {
	m := &Memory{
		Name:        row.Name,
		Type:        MemoryType(row.Type),
		Content:     row.Content,
		Description: row.Description,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
		CreatedBy:   row.CreatedBy,
	}
	if row.TagsJSON != "" {
		_ = json.Unmarshal([]byte(row.TagsJSON), &m.Tags)
	}
	return m
}

// ReaderAdapter satisfies agent.MemoryReader against a SQL-backed
// MemoryStore. Brief B / C use this to wire prompt generation against the
// new store without taking a direct dependency on the implementation.
type ReaderAdapter struct {
	Store  store.MemoryStore
	RepoID string
	// Ctx is consulted on every read. Callers that span long-lived
	// generation can pass a per-request context.
	Ctx context.Context
}

// ReadByName implements agent.MemoryReader.
func (r ReaderAdapter) ReadByName(name string) (*Memory, error) {
	ctx := r.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	row, err := r.Store.Get(ctx, r.RepoID, name)
	if err != nil {
		return nil, err
	}
	return rowToMemory(row), nil
}

