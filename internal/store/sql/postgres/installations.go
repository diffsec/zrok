package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type installationStore struct{ db *sql.DB }

func (s *installationStore) Create(ctx context.Context, i *store.Installation) error {
	if i.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		i.ID = id.String()
	}
	now := time.Now().UTC()
	if i.CreatedAt.IsZero() {
		i.CreatedAt = now
	}
	i.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO installations(id,org_id,github_installation_id,account_login,account_type,target_type,permissions_json,events_json,suspended_at,created_at,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		i.ID, i.OrgID, i.GitHubInstallationID, i.AccountLogin, i.AccountType, i.TargetType,
		nullJSON(i.PermissionsJSON), nullJSON(i.EventsJSON), i.SuspendedAt, i.CreatedAt, i.UpdatedAt)
	return err
}

func (s *installationStore) Get(ctx context.Context, id string) (*store.Installation, error) {
	row := s.db.QueryRowContext(ctx, installationSelect+` WHERE id=$1`, id)
	return scanInstallation(row.Scan)
}

func (s *installationStore) GetByGitHubID(ctx context.Context, ghID int64) (*store.Installation, error) {
	row := s.db.QueryRowContext(ctx, installationSelect+` WHERE github_installation_id=$1`, ghID)
	return scanInstallation(row.Scan)
}

func (s *installationStore) Update(ctx context.Context, i *store.Installation) error {
	i.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE installations SET account_login=$1,account_type=$2,target_type=$3,permissions_json=$4,events_json=$5,suspended_at=$6,updated_at=$7 WHERE id=$8`,
		i.AccountLogin, i.AccountType, i.TargetType, nullJSON(i.PermissionsJSON),
		nullJSON(i.EventsJSON), i.SuspendedAt, i.UpdatedAt, i.ID)
	return err
}

func (s *installationStore) List(ctx context.Context, orgID string) ([]*store.Installation, error) {
	rows, err := s.db.QueryContext(ctx, installationSelect+` WHERE org_id=$1 ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Installation
	for rows.Next() {
		i, err := scanInstallation(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

const installationSelect = `SELECT id,org_id,github_installation_id,account_login,account_type,target_type,COALESCE(permissions_json::text,''),COALESCE(events_json::text,''),suspended_at,created_at,updated_at FROM installations`

func scanInstallation(scan func(...any) error) (*store.Installation, error) {
	i := &store.Installation{}
	var suspended sql.NullTime
	if err := scan(&i.ID, &i.OrgID, &i.GitHubInstallationID, &i.AccountLogin,
		&i.AccountType, &i.TargetType, &i.PermissionsJSON, &i.EventsJSON,
		&suspended, &i.CreatedAt, &i.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if suspended.Valid {
		ts := suspended.Time
		i.SuspendedAt = &ts
	}
	return i, nil
}
