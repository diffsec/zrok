package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type workflowStore struct{ db *sql.DB }

func (s *workflowStore) Create(ctx context.Context, w *store.Workflow) error {
	if w.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		w.ID = id.String()
	}
	now := time.Now().UTC()
	if w.CreatedAt.IsZero() {
		w.CreatedAt = now
	}
	w.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO workflows(id,org_id,repo_id,name,active_version_id,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		w.ID, w.OrgID, nullStr(w.RepoID), w.Name, nullStr(w.ActiveVersionID),
		w.CreatedAt, w.UpdatedAt)
	return err
}

func (s *workflowStore) Get(ctx context.Context, id string) (*store.Workflow, error) {
	row := s.db.QueryRowContext(ctx, workflowSelect+` WHERE id=?`, id)
	return scanWorkflow(row.Scan)
}

func (s *workflowStore) GetActiveForRepo(ctx context.Context, orgID, repoID string) (*store.Workflow, *store.WorkflowVersion, error) {
	// Prefer a repo-specific override, fall back to the org default.
	var w *store.Workflow
	row := s.db.QueryRowContext(ctx,
		workflowSelect+` WHERE org_id=? AND repo_id=? ORDER BY created_at DESC LIMIT 1`,
		orgID, repoID)
	wf, err := scanWorkflow(row.Scan)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	w = wf
	if w == nil {
		row = s.db.QueryRowContext(ctx,
			workflowSelect+` WHERE org_id=? AND repo_id IS NULL ORDER BY created_at DESC LIMIT 1`,
			orgID)
		wf, err = scanWorkflow(row.Scan)
		if err != nil {
			return nil, nil, err
		}
		w = wf
	}
	if w.ActiveVersionID == "" {
		return w, nil, store.ErrNotFound
	}
	v, err := s.GetVersion(ctx, w.ActiveVersionID)
	if err != nil {
		return w, nil, err
	}
	return w, v, nil
}

func (s *workflowStore) List(ctx context.Context, orgID string) ([]*store.Workflow, error) {
	rows, err := s.db.QueryContext(ctx, workflowSelect+` WHERE org_id=? ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Workflow
	for rows.Next() {
		w, err := scanWorkflow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *workflowStore) NewVersion(ctx context.Context, v *store.WorkflowVersion) error {
	if v.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		v.ID = id.String()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	if v.Version == 0 {
		row := s.db.QueryRowContext(ctx,
			`SELECT COALESCE(MAX(version),0)+1 FROM workflow_versions WHERE workflow_id=?`,
			v.WorkflowID)
		_ = row.Scan(&v.Version)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO workflow_versions(id,workflow_id,version,yaml,created_by,created_at)
		 VALUES(?,?,?,?,?,?)`,
		v.ID, v.WorkflowID, v.Version, v.YAML, nullStr(v.CreatedBy), v.CreatedAt)
	return err
}

func (s *workflowStore) GetVersion(ctx context.Context, id string) (*store.WorkflowVersion, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,workflow_id,version,yaml,COALESCE(created_by,''),created_at FROM workflow_versions WHERE id=?`,
		id)
	v := &store.WorkflowVersion{}
	if err := row.Scan(&v.ID, &v.WorkflowID, &v.Version, &v.YAML, &v.CreatedBy, &v.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return v, nil
}

func (s *workflowStore) SetActiveVersion(ctx context.Context, workflowID, versionID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE workflows SET active_version_id=?, updated_at=? WHERE id=?`,
		versionID, time.Now().UTC(), workflowID)
	return err
}

const workflowSelect = `SELECT id,org_id,COALESCE(repo_id,''),name,COALESCE(active_version_id,''),created_at,updated_at FROM workflows`

func scanWorkflow(scan func(...any) error) (*store.Workflow, error) {
	w := &store.Workflow{}
	if err := scan(&w.ID, &w.OrgID, &w.RepoID, &w.Name, &w.ActiveVersionID, &w.CreatedAt, &w.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return w, nil
}
