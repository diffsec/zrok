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
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT(idempotency_key) DO NOTHING`,
		j.ID, j.JobType, nullJSON(j.PayloadJSON), j.IdempotencyKey, j.Status, j.Attempts,
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
	// Postgres can do this atomically with SELECT FOR UPDATE SKIP LOCKED +
	// UPDATE...RETURNING.
	row := s.db.QueryRowContext(ctx,
		`UPDATE enqueued_jobs SET status='running', locked_at=$1, locked_by=$2, attempts=attempts+1, updated_at=$1
		 WHERE id = (
		   SELECT id FROM enqueued_jobs
		   WHERE status='pending' AND run_after<=$1
		   ORDER BY run_after, id
		   FOR UPDATE SKIP LOCKED
		   LIMIT 1
		 )
		 RETURNING id,job_type,COALESCE(payload_json::text,''),idempotency_key,status,attempts,run_after,created_at,updated_at,locked_at,COALESCE(locked_by,''),COALESCE(last_error,'')`,
		now, workerID)
	j, err := scanJob(row.Scan)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return j, nil
}

func (s *jobStore) Complete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE enqueued_jobs SET status='done', updated_at=$1 WHERE id=$2`,
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
	if len(errMsg) > 4000 {
		errMsg = errMsg[:4000]
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE enqueued_jobs SET status=$1, last_error=$2, run_after=$3, updated_at=$4, locked_at=NULL, locked_by=NULL WHERE id=$5`,
		status, strings.TrimSpace(errMsg), runAfter, now, id)
	return err
}

func (s *jobStore) Get(ctx context.Context, id string) (*store.EnqueuedJob, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,job_type,COALESCE(payload_json::text,''),idempotency_key,status,attempts,run_after,created_at,updated_at,locked_at,COALESCE(locked_by,''),COALESCE(last_error,'')
		 FROM enqueued_jobs WHERE id=$1`, id)
	return scanJob(row.Scan)
}

func (s *jobStore) GetByKey(ctx context.Context, key string) (*store.EnqueuedJob, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,job_type,COALESCE(payload_json::text,''),idempotency_key,status,attempts,run_after,created_at,updated_at,locked_at,COALESCE(locked_by,''),COALESCE(last_error,'')
		 FROM enqueued_jobs WHERE idempotency_key=$1`, key)
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
