package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type runStore struct{ db *sql.DB }

func (s *runStore) Create(ctx context.Context, r *store.Run) error {
	if r.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		r.ID = id.String()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.Status == "" {
		r.Status = "queued"
	}
	prNum := sql.NullInt64{}
	if r.PRNumber > 0 {
		prNum = sql.NullInt64{Int64: int64(r.PRNumber), Valid: true}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO runs(id,repo_id,workflow_version_id,trigger,pr_number,base_sha,head_sha,status,error_category,error_message,triggered_by,created_at,started_at,completed_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		r.ID, r.RepoID, nullStr(r.WorkflowVersionID), r.Trigger, prNum,
		nullStr(r.BaseSHA), nullStr(r.HeadSHA), r.Status,
		nullStr(r.ErrorCategory), nullStr(r.ErrorMessage), nullStr(r.TriggeredBy),
		r.CreatedAt, r.StartedAt, r.CompletedAt)
	return err
}

func (s *runStore) Get(ctx context.Context, id string) (*store.Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, runSelectByID, id))
}

func (s *runStore) List(ctx context.Context, repoID string, limit, offset int) ([]*store.Run, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+runSelectColumns+` FROM runs WHERE repo_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		repoID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Run
	for rows.Next() {
		r, err := scanRunRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *runStore) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET status=$1 WHERE id=$2`, status, id)
	return err
}

const runSelectColumns = `id,repo_id,COALESCE(workflow_version_id::text,''),trigger,pr_number,COALESCE(base_sha,''),COALESCE(head_sha,''),status,COALESCE(error_category,''),COALESCE(error_message,''),COALESCE(triggered_by::text,''),created_at,started_at,completed_at`

var runSelectByID = "SELECT " + runSelectColumns + " FROM runs WHERE id=$1"

func scanRun(row *sql.Row) (*store.Run, error) {
	r := &store.Run{}
	var prNum sql.NullInt64
	var startedAt, completedAt sql.NullTime
	if err := row.Scan(&r.ID, &r.RepoID, &r.WorkflowVersionID, &r.Trigger, &prNum,
		&r.BaseSHA, &r.HeadSHA, &r.Status, &r.ErrorCategory, &r.ErrorMessage, &r.TriggeredBy,
		&r.CreatedAt, &startedAt, &completedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	r.PRNumber = int(prNum.Int64)
	if startedAt.Valid {
		ts := startedAt.Time
		r.StartedAt = &ts
	}
	if completedAt.Valid {
		ts := completedAt.Time
		r.CompletedAt = &ts
	}
	return r, nil
}

func scanRunRows(rows *sql.Rows) (*store.Run, error) {
	r := &store.Run{}
	var prNum sql.NullInt64
	var startedAt, completedAt sql.NullTime
	if err := rows.Scan(&r.ID, &r.RepoID, &r.WorkflowVersionID, &r.Trigger, &prNum,
		&r.BaseSHA, &r.HeadSHA, &r.Status, &r.ErrorCategory, &r.ErrorMessage, &r.TriggeredBy,
		&r.CreatedAt, &startedAt, &completedAt); err != nil {
		return nil, err
	}
	r.PRNumber = int(prNum.Int64)
	if startedAt.Valid {
		ts := startedAt.Time
		r.StartedAt = &ts
	}
	if completedAt.Valid {
		ts := completedAt.Time
		r.CompletedAt = &ts
	}
	return r, nil
}
