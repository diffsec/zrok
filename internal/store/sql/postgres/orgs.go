package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type orgStore struct{ db *sql.DB }

func (s *orgStore) Create(ctx context.Context, o *store.Org) error {
	if o.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		o.ID = id.String()
	}
	now := time.Now().UTC()
	if o.CreatedAt.IsZero() {
		o.CreatedAt = now
	}
	o.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO organizations(id,name,github_login,created_at,updated_at) VALUES($1,$2,$3,$4,$5)`,
		o.ID, o.Name, nullStr(o.GitHubLogin), o.CreatedAt, o.UpdatedAt)
	return err
}

func (s *orgStore) Get(ctx context.Context, id string) (*store.Org, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,COALESCE(github_login,''),created_at,updated_at FROM organizations WHERE id=$1`, id)
	o := &store.Org{}
	if err := row.Scan(&o.ID, &o.Name, &o.GitHubLogin, &o.CreatedAt, &o.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return o, nil
}

func (s *orgStore) GetByGitHubLogin(ctx context.Context, login string) (*store.Org, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,COALESCE(github_login,''),created_at,updated_at FROM organizations WHERE github_login=$1`, login)
	o := &store.Org{}
	if err := row.Scan(&o.ID, &o.Name, &o.GitHubLogin, &o.CreatedAt, &o.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return o, nil
}

func (s *orgStore) Update(ctx context.Context, o *store.Org) error {
	o.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE organizations SET name=$1,github_login=$2,updated_at=$3 WHERE id=$4`,
		o.Name, nullStr(o.GitHubLogin), o.UpdatedAt, o.ID)
	return err
}

func (s *orgStore) List(ctx context.Context) ([]*store.Org, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,COALESCE(github_login,''),created_at,updated_at FROM organizations ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Org
	for rows.Next() {
		o := &store.Org{}
		if err := rows.Scan(&o.ID, &o.Name, &o.GitHubLogin, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func nullStr(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}
