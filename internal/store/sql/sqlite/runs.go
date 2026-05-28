package sqlite

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
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
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
		`SELECT `+runSelectColumns+` FROM runs WHERE repo_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
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
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET status=? WHERE id=?`, status, id)
	return err
}

func (s *runStore) GetByRepoAndHead(ctx context.Context, repoID, headSHA string) (*store.Run, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+runSelectColumns+` FROM runs WHERE repo_id=? AND head_sha=? ORDER BY created_at DESC LIMIT 1`,
		repoID, headSHA)
	return scanRun(row)
}

func (s *runStore) UpdateError(ctx context.Context, id, category, message string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET error_category=?, error_message=? WHERE id=?`,
		nullStr(category), nullStr(message), id)
	return err
}

func (s *runStore) MarkStarted(ctx context.Context, id string, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET started_at=? WHERE id=? AND started_at IS NULL`, t, id)
	return err
}

func (s *runStore) MarkCompleted(ctx context.Context, id, status string, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET status=?, completed_at=? WHERE id=?`, status, t, id)
	return err
}

func (s *runStore) Cancel(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE runs SET status='cancelled', completed_at=? WHERE id=? AND status NOT IN ('completed','failed','cancelled')`,
		time.Now().UTC(), id)
	return err
}

const runSelectColumns = `id,repo_id,workflow_version_id,trigger,pr_number,base_sha,head_sha,status,error_category,error_message,triggered_by,created_at,started_at,completed_at`

var runSelectByID = "SELECT " + runSelectColumns + " FROM runs WHERE id=?"

func scanRun(row *sql.Row) (*store.Run, error) {
	r := &store.Run{}
	var workflowVersionID, baseSHA, headSHA, errCat, errMsg, triggeredBy sql.NullString
	var prNum sql.NullInt64
	var startedAt, completedAt sql.NullTime
	if err := row.Scan(&r.ID, &r.RepoID, &workflowVersionID, &r.Trigger, &prNum,
		&baseSHA, &headSHA, &r.Status, &errCat, &errMsg, &triggeredBy,
		&r.CreatedAt, &startedAt, &completedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	r.WorkflowVersionID = workflowVersionID.String
	r.PRNumber = int(prNum.Int64)
	r.BaseSHA = baseSHA.String
	r.HeadSHA = headSHA.String
	r.ErrorCategory = errCat.String
	r.ErrorMessage = errMsg.String
	r.TriggeredBy = triggeredBy.String
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
	var workflowVersionID, baseSHA, headSHA, errCat, errMsg, triggeredBy sql.NullString
	var prNum sql.NullInt64
	var startedAt, completedAt sql.NullTime
	if err := rows.Scan(&r.ID, &r.RepoID, &workflowVersionID, &r.Trigger, &prNum,
		&baseSHA, &headSHA, &r.Status, &errCat, &errMsg, &triggeredBy,
		&r.CreatedAt, &startedAt, &completedAt); err != nil {
		return nil, err
	}
	r.WorkflowVersionID = workflowVersionID.String
	r.PRNumber = int(prNum.Int64)
	r.BaseSHA = baseSHA.String
	r.HeadSHA = headSHA.String
	r.ErrorCategory = errCat.String
	r.ErrorMessage = errMsg.String
	r.TriggeredBy = triggeredBy.String
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
