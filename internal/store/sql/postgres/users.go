package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type userStore struct{ db *sql.DB }

func (s *userStore) Create(ctx context.Context, u *store.User) error {
	if u.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		u.ID = id.String()
	}
	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	if u.Role == "" {
		u.Role = "member"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users(id,org_id,github_id,github_login,email,name,avatar_url,role,created_at,updated_at,last_login_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		u.ID, u.OrgID, nullInt64(u.GitHubID), u.GitHubLogin, nullStr(u.Email), nullStr(u.Name),
		nullStr(u.AvatarURL), u.Role, u.CreatedAt, u.UpdatedAt, u.LastLoginAt)
	return err
}

func (s *userStore) Get(ctx context.Context, id string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelectByID, id))
}

func (s *userStore) GetByGitHubID(ctx context.Context, ghID int64) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelectByGHID, ghID))
}

func (s *userStore) GetByGitHubLogin(ctx context.Context, orgID, login string) (*store.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, userSelectByLogin, orgID, login))
}

func (s *userStore) Update(ctx context.Context, u *store.User) error {
	u.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET email=$1,name=$2,avatar_url=$3,role=$4,updated_at=$5,last_login_at=$6 WHERE id=$7`,
		nullStr(u.Email), nullStr(u.Name), nullStr(u.AvatarURL), u.Role, u.UpdatedAt, u.LastLoginAt, u.ID)
	return err
}

func (s *userStore) List(ctx context.Context, orgID string) ([]*store.User, error) {
	rows, err := s.db.QueryContext(ctx, userSelectListByOrg, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.User
	for rows.Next() {
		u, err := scanUserRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

const userSelectColumns = `id,org_id,COALESCE(github_id,0),github_login,COALESCE(email,''),COALESCE(name,''),COALESCE(avatar_url,''),role,created_at,updated_at,last_login_at`

var (
	userSelectByID      = "SELECT " + userSelectColumns + " FROM users WHERE id=$1"
	userSelectByGHID    = "SELECT " + userSelectColumns + " FROM users WHERE github_id=$1"
	userSelectByLogin   = "SELECT " + userSelectColumns + " FROM users WHERE org_id=$1 AND github_login=$2"
	userSelectListByOrg = "SELECT " + userSelectColumns + " FROM users WHERE org_id=$1 ORDER BY github_login"
)

func scanUser(row *sql.Row) (*store.User, error) {
	u := &store.User{}
	if err := row.Scan(&u.ID, &u.OrgID, &u.GitHubID, &u.GitHubLogin, &u.Email, &u.Name, &u.AvatarURL,
		&u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

func scanUserRows(rows *sql.Rows) (*store.User, error) {
	u := &store.User{}
	if err := rows.Scan(&u.ID, &u.OrgID, &u.GitHubID, &u.GitHubLogin, &u.Email, &u.Name, &u.AvatarURL,
		&u.Role, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt); err != nil {
		return nil, err
	}
	return u, nil
}

func nullInt64(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}
