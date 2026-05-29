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

type jobStore struct{ db *sql.DB }

func (s *jobStore) Enqueue(ctx context.Context, j *store.EnqueuedJob) (*store.EnqueuedJob, bool, error) {
	if j.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, false, err
		}
		j.ID = id.String()
	}
	now := time.Now().UTC()
	if j.CreatedAt.IsZero() {
		j.CreatedAt = now
	}
	j.UpdatedAt = now
	if j.RunAfter.IsZero() {
		j.RunAfter = now
	}
	if j.Status == "" {
		j.Status = "pending"
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO enqueued_jobs(id,job_type,payload_json,idempotency_key,status,attempts,run_after,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(idempotency_key) DO NOTHING`,
		j.ID, j.JobType, j.PayloadJSON, j.IdempotencyKey, j.Status, j.Attempts,
		j.RunAfter, j.CreatedAt, j.UpdatedAt)
	if err != nil {
		return nil, false, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return j, true, nil
	}
	existing, err := s.GetByKey(ctx, j.IdempotencyKey)
	if err != nil {
		return nil, false, err
	}
	return existing, false, nil
}

func (s *jobStore) Claim(ctx context.Context, workerID string, now time.Time) (*store.EnqueuedJob, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	row := tx.QueryRowContext(ctx,
		`SELECT id,job_type,payload_json,idempotency_key,status,attempts,run_after,created_at,updated_at,locked_at,locked_by,COALESCE(last_error,'')
		 FROM enqueued_jobs
		 WHERE status='pending' AND run_after<=?
		 ORDER BY run_after, id LIMIT 1`, now)
	j := &store.EnqueuedJob{}
	var locked sql.NullTime
	var lockedBy sql.NullString
	if err := row.Scan(&j.ID, &j.JobType, &j.PayloadJSON, &j.IdempotencyKey, &j.Status,
		&j.Attempts, &j.RunAfter, &j.CreatedAt, &j.UpdatedAt, &locked, &lockedBy, &j.LastError); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE enqueued_jobs SET status='running', locked_at=?, locked_by=?, attempts=attempts+1, updated_at=?
		 WHERE id=? AND status='pending'`,
		now, workerID, now, j.ID)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Someone else claimed it; treat as no work for this tick.
		return nil, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	j.Status = "running"
	j.LockedAt = &now
	j.LockedBy = workerID
	j.Attempts++
	return j, nil
}

func (s *jobStore) Complete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE enqueued_jobs SET status='done', updated_at=? WHERE id=?`,
		time.Now().UTC(), id)
	return err
}

func (s *jobStore) Fail(ctx context.Context, id string, errMsg string, retry bool) error {
	now := time.Now().UTC()
	status := "failed"
	runAfter := now
	if retry {
		status = "pending"
		runAfter = now.Add(30 * time.Second)
	}
	// Truncate long error messages.
	if len(errMsg) > 4000 {
		errMsg = errMsg[:4000]
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE enqueued_jobs SET status=?, last_error=?, run_after=?, updated_at=?, locked_at=NULL, locked_by=NULL WHERE id=?`,
		status, strings.TrimSpace(errMsg), runAfter, now, id)
	return err
}

func (s *jobStore) Get(ctx context.Context, id string) (*store.EnqueuedJob, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,job_type,payload_json,idempotency_key,status,attempts,run_after,created_at,updated_at,locked_at,COALESCE(locked_by,''),COALESCE(last_error,'')
		 FROM enqueued_jobs WHERE id=?`, id)
	return scanJob(row.Scan)
}

func (s *jobStore) GetByKey(ctx context.Context, key string) (*store.EnqueuedJob, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,job_type,payload_json,idempotency_key,status,attempts,run_after,created_at,updated_at,locked_at,COALESCE(locked_by,''),COALESCE(last_error,'')
		 FROM enqueued_jobs WHERE idempotency_key=?`, key)
	return scanJob(row.Scan)
}

func scanJob(scan func(...any) error) (*store.EnqueuedJob, error) {
	j := &store.EnqueuedJob{}
	var locked sql.NullTime
	if err := scan(&j.ID, &j.JobType, &j.PayloadJSON, &j.IdempotencyKey, &j.Status,
		&j.Attempts, &j.RunAfter, &j.CreatedAt, &j.UpdatedAt, &locked, &j.LockedBy, &j.LastError); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if locked.Valid {
		ts := locked.Time
		j.LockedAt = &ts
	}
	return j, nil
}
