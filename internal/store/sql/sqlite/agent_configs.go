package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type agentConfigStore struct{ db *sql.DB }

func (s *agentConfigStore) Create(ctx context.Context, ac *store.AgentConfigRow) error {
	if ac.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		ac.ID = id.String()
	}
	now := time.Now().UTC()
	if ac.CreatedAt.IsZero() {
		ac.CreatedAt = now
	}
	ac.UpdatedAt = now
	if ac.Source == "" {
		ac.Source = "builtin"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_configs(id,org_id,name,description,phase,source,active_revision_id,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(org_id,name) DO UPDATE SET
		   description=excluded.description,
		   phase=excluded.phase,
		   source=excluded.source,
		   updated_at=excluded.updated_at`,
		ac.ID, ac.OrgID, ac.Name, nullStr(ac.Description), ac.Phase, ac.Source,
		nullStr(ac.ActiveRevisionID), ac.CreatedAt, ac.UpdatedAt)
	return err
}

func (s *agentConfigStore) Get(ctx context.Context, id string) (*store.AgentConfigRow, error) {
	row := s.db.QueryRowContext(ctx, agentConfigSelect+` WHERE id=?`, id)
	return scanAgentConfig(row.Scan)
}

func (s *agentConfigStore) GetByName(ctx context.Context, orgID, name string) (*store.AgentConfigRow, error) {
	row := s.db.QueryRowContext(ctx, agentConfigSelect+` WHERE org_id=? AND name=?`, orgID, name)
	return scanAgentConfig(row.Scan)
}

func (s *agentConfigStore) List(ctx context.Context, orgID string) ([]*store.AgentConfigRow, error) {
	rows, err := s.db.QueryContext(ctx, agentConfigSelect+` WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.AgentConfigRow
	for rows.Next() {
		ac, err := scanAgentConfig(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, ac)
	}
	return out, rows.Err()
}

func (s *agentConfigStore) NewRevision(ctx context.Context, rev *store.AgentConfigRevision) error {
	if rev.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		rev.ID = id.String()
	}
	if rev.CreatedAt.IsZero() {
		rev.CreatedAt = time.Now().UTC()
	}
	// Auto-increment revision number when zero.
	if rev.Revision == 0 {
		row := s.db.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(revision),0)+1 FROM agent_config_revisions WHERE agent_config_id=?`,
			rev.AgentConfigID)
		_ = row.Scan(&rev.Revision)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_config_revisions(id,agent_config_id,revision,yaml,model_config_json,import_sha,created_by,created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		rev.ID, rev.AgentConfigID, rev.Revision, rev.YAML,
		nullStr(rev.ModelConfigJSON), nullStr(rev.ImportSHA),
		nullStr(rev.CreatedBy), rev.CreatedAt)
	return err
}

func (s *agentConfigStore) ListRevisions(ctx context.Context, agentConfigID string) ([]*store.AgentConfigRevision, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,agent_config_id,revision,yaml,COALESCE(model_config_json,''),COALESCE(import_sha,''),COALESCE(created_by,''),created_at
		 FROM agent_config_revisions WHERE agent_config_id=? ORDER BY revision DESC`,
		agentConfigID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.AgentConfigRevision
	for rows.Next() {
		r := &store.AgentConfigRevision{}
		if err := rows.Scan(&r.ID, &r.AgentConfigID, &r.Revision, &r.YAML,
			&r.ModelConfigJSON, &r.ImportSHA, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *agentConfigStore) SetActiveRevision(ctx context.Context, agentConfigID, revisionID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agent_configs SET active_revision_id=?, updated_at=? WHERE id=?`,
		revisionID, time.Now().UTC(), agentConfigID)
	return err
}

const agentConfigSelect = `SELECT id,org_id,name,COALESCE(description,''),phase,source,COALESCE(active_revision_id,''),created_at,updated_at FROM agent_configs`

func scanAgentConfig(scan func(...any) error) (*store.AgentConfigRow, error) {
	ac := &store.AgentConfigRow{}
	if err := scan(&ac.ID, &ac.OrgID, &ac.Name, &ac.Description, &ac.Phase,
		&ac.Source, &ac.ActiveRevisionID, &ac.CreatedAt, &ac.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return ac, nil
}
