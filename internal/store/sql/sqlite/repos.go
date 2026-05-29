package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type repoStore struct{ db *sql.DB }

func (s *repoStore) Create(ctx context.Context, r *store.Repository) error {
	if r.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		r.ID = id.String()
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	if r.State == "" {
		r.State = "pending"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO repositories(id,org_id,installation_id,github_repo_id,full_name,default_branch,private,state,classification_json,last_indexed_at,last_indexed_sha,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.OrgID, nullStr(r.InstallationID), r.GitHubRepoID, r.FullName,
		nullStr(r.DefaultBranch), boolToInt(r.Private), r.State,
		nullStr(r.ClassificationJSON), r.LastIndexedAt, nullStr(r.LastIndexedSHA),
		r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *repoStore) Get(ctx context.Context, id string) (*store.Repository, error) {
	return scanRepo(s.db.QueryRowContext(ctx, repoSelectByID, id))
}

func (s *repoStore) GetByGitHubID(ctx context.Context, ghID int64) (*store.Repository, error) {
	return scanRepo(s.db.QueryRowContext(ctx, repoSelectByGHID, ghID))
}

func (s *repoStore) GetByFullName(ctx context.Context, orgID, fullName string) (*store.Repository, error) {
	return scanRepo(s.db.QueryRowContext(ctx, repoSelectByFullName, orgID, fullName))
}

func (s *repoStore) Update(ctx context.Context, r *store.Repository) error {
	r.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE repositories
		   SET installation_id=?, default_branch=?, private=?, state=?, classification_json=?,
		       last_indexed_at=?, last_indexed_sha=?, updated_at=?
		 WHERE id=?`,
		nullStr(r.InstallationID), nullStr(r.DefaultBranch), boolToInt(r.Private), r.State,
		nullStr(r.ClassificationJSON), r.LastIndexedAt, nullStr(r.LastIndexedSHA),
		r.UpdatedAt, r.ID)
	return err
}

func (s *repoStore) List(ctx context.Context, orgID string) ([]*store.Repository, error) {
	rows, err := s.db.QueryContext(ctx, repoSelectListByOrg, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Repository
	for rows.Next() {
		r, err := scanRepoRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const repoSelectColumns = `id,org_id,installation_id,github_repo_id,full_name,default_branch,private,state,classification_json,last_indexed_at,last_indexed_sha,created_at,updated_at`

var (
	repoSelectByID       = "SELECT " + repoSelectColumns + " FROM repositories WHERE id=?"
	repoSelectByGHID     = "SELECT " + repoSelectColumns + " FROM repositories WHERE github_repo_id=?"
	repoSelectByFullName = "SELECT " + repoSelectColumns + " FROM repositories WHERE org_id=? AND full_name=?"
	repoSelectListByOrg  = "SELECT " + repoSelectColumns + " FROM repositories WHERE org_id=? ORDER BY full_name"
)

func scanRepo(row *sql.Row) (*store.Repository, error) {
	r := &store.Repository{}
	var installationID, defaultBranch, classification, lastIndexedSHA sql.NullString
	var lastIndexedAt sql.NullTime
	var private int
	if err := row.Scan(&r.ID, &r.OrgID, &installationID, &r.GitHubRepoID, &r.FullName,
		&defaultBranch, &private, &r.State, &classification, &lastIndexedAt, &lastIndexedSHA,
		&r.CreatedAt, &r.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	r.InstallationID = installationID.String
	r.DefaultBranch = defaultBranch.String
	r.Private = private != 0
	r.ClassificationJSON = classification.String
	r.LastIndexedSHA = lastIndexedSHA.String
	if lastIndexedAt.Valid {
		ts := lastIndexedAt.Time
		r.LastIndexedAt = &ts
	}
	return r, nil
}

func scanRepoRows(rows *sql.Rows) (*store.Repository, error) {
	r := &store.Repository{}
	var installationID, defaultBranch, classification, lastIndexedSHA sql.NullString
	var lastIndexedAt sql.NullTime
	var private int
	if err := rows.Scan(&r.ID, &r.OrgID, &installationID, &r.GitHubRepoID, &r.FullName,
		&defaultBranch, &private, &r.State, &classification, &lastIndexedAt, &lastIndexedSHA,
		&r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.InstallationID = installationID.String
	r.DefaultBranch = defaultBranch.String
	r.Private = private != 0
	r.ClassificationJSON = classification.String
	r.LastIndexedSHA = lastIndexedSHA.String
	if lastIndexedAt.Valid {
		ts := lastIndexedAt.Time
		r.LastIndexedAt = &ts
	}
	return r, nil
}
