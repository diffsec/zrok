package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type memoryStore struct{ db *sql.DB }

func (s *memoryStore) Upsert(ctx context.Context, m *store.MemoryRow) error {
	if m.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		m.ID = id.String()
	}
	now := time.Now().UTC()
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	m.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO memories(id,repo_id,name,type,content,description,tags_json,created_by,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(repo_id,name) DO UPDATE SET
		   type=excluded.type,
		   content=excluded.content,
		   description=excluded.description,
		   tags_json=excluded.tags_json,
		   updated_at=excluded.updated_at`,
		m.ID, m.RepoID, m.Name, m.Type, m.Content, nullStr(m.Description),
		nullStr(m.TagsJSON), nullStr(m.CreatedBy), m.CreatedAt, m.UpdatedAt)
	return err
}

func (s *memoryStore) Get(ctx context.Context, repoID, name string) (*store.MemoryRow, error) {
	row := s.db.QueryRowContext(ctx, selectMemorySQL+` WHERE repo_id=? AND name=?`, repoID, name)
	return scanMemory(row.Scan)
}

func (s *memoryStore) List(ctx context.Context, repoID, memType string) ([]*store.MemoryRow, error) {
	var rows *sql.Rows
	var err error
	if memType == "" {
		rows, err = s.db.QueryContext(ctx, selectMemorySQL+` WHERE repo_id=? ORDER BY name`, repoID)
	} else {
		rows, err = s.db.QueryContext(ctx, selectMemorySQL+` WHERE repo_id=? AND type=? ORDER BY name`, repoID, memType)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.MemoryRow
	for rows.Next() {
		m, err := scanMemory(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *memoryStore) Delete(ctx context.Context, repoID, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM memories WHERE repo_id=? AND name=?`, repoID, name)
	return err
}

// Search uses LIKE-based substring matching across name/content/description.
// The FTS5 virtual table from the migration would give better ranking but
// also requires triggers to keep in sync; this implementation falls back to
// a portable LIKE scan that works for the v1 acceptance criteria.
func (s *memoryStore) Search(ctx context.Context, repoID, query string) ([]*store.MemoryRow, error) {
	q := "%" + strings.ToLower(query) + "%"
	rows, err := s.db.QueryContext(ctx,
		selectMemorySQL+` WHERE repo_id=? AND (
		    LOWER(name) LIKE ? OR LOWER(content) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?
		    OR LOWER(COALESCE(tags_json,'')) LIKE ?
		) ORDER BY name`, repoID, q, q, q, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.MemoryRow
	for rows.Next() {
		m, err := scanMemory(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

const selectMemorySQL = `SELECT id,repo_id,name,type,content,COALESCE(description,''),
    COALESCE(tags_json,''),COALESCE(created_by,''),created_at,updated_at FROM memories`

func scanMemory(scan func(...any) error) (*store.MemoryRow, error) {
	m := &store.MemoryRow{}
	if err := scan(&m.ID, &m.RepoID, &m.Name, &m.Type, &m.Content, &m.Description,
		&m.TagsJSON, &m.CreatedBy, &m.CreatedAt, &m.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return m, nil
}
