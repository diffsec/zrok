package postgres

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
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT(repo_id,name) DO UPDATE SET
		   type=EXCLUDED.type,
		   content=EXCLUDED.content,
		   description=EXCLUDED.description,
		   tags_json=EXCLUDED.tags_json,
		   updated_at=EXCLUDED.updated_at`,
		m.ID, m.RepoID, m.Name, m.Type, m.Content, nullStr(m.Description),
		nullJSON(m.TagsJSON), nullStr(m.CreatedBy), m.CreatedAt, m.UpdatedAt)
	return err
}

func (s *memoryStore) Get(ctx context.Context, repoID, name string) (*store.MemoryRow, error) {
	row := s.db.QueryRowContext(ctx, selectMemorySQL+` WHERE repo_id=$1 AND name=$2`, repoID, name)
	return scanMemory(row.Scan)
}

func (s *memoryStore) List(ctx context.Context, repoID, memType string) ([]*store.MemoryRow, error) {
	var rows *sql.Rows
	var err error
	if memType == "" {
		rows, err = s.db.QueryContext(ctx, selectMemorySQL+` WHERE repo_id=$1 ORDER BY name`, repoID)
	} else {
		rows, err = s.db.QueryContext(ctx, selectMemorySQL+` WHERE repo_id=$1 AND type=$2 ORDER BY name`, repoID, memType)
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
	_, err := s.db.ExecContext(ctx, `DELETE FROM memories WHERE repo_id=$1 AND name=$2`, repoID, name)
	return err
}

// Search uses Postgres full-text via the search_tsv column populated by the
// trigger from the migration. Falls back to a plain ILIKE scan when the
// query parser rejects the input (e.g. raw boolean operators).
func (s *memoryStore) Search(ctx context.Context, repoID, query string) ([]*store.MemoryRow, error) {
	rows, err := s.db.QueryContext(ctx,
		selectMemorySQL+` WHERE repo_id=$1 AND search_tsv @@ plainto_tsquery('english', $2)
		 ORDER BY ts_rank(search_tsv, plainto_tsquery('english', $2)) DESC`,
		repoID, query)
	if err != nil {
		// Fall back to ILIKE if tsquery parsing failed.
		q := "%" + strings.ToLower(query) + "%"
		rows, err = s.db.QueryContext(ctx,
			selectMemorySQL+` WHERE repo_id=$1 AND (
			    LOWER(name) LIKE $2 OR LOWER(content) LIKE $2 OR LOWER(COALESCE(description,'')) LIKE $2
			) ORDER BY name`, repoID, q)
		if err != nil {
			return nil, err
		}
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
    COALESCE(tags_json::text,''),COALESCE(created_by,''),created_at,updated_at FROM memories`

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
