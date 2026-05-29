// Package queue defines the Queue interface plus the in-process SQLite-backed
// implementation used by the solo deploy mode. The asynq (Redis) impl ships
// later — the same Queue interface is satisfied either way.
package queue

import (
	"context"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

// Job is the transport-agnostic shape a Queue moves around.
type Job struct {
	ID             string
	Type           string
	PayloadJSON    string
	IdempotencyKey string
	Attempts       int
	RunAfter       time.Time
}

// Queue is the producer + consumer surface.
//
// Enqueue is idempotent on IdempotencyKey — duplicates return inserted=false
// and the existing job. Dequeue returns nil/nil when there is no work
// available right now. Complete/Fail finalize a claimed job.
type Queue interface {
	Enqueue(ctx context.Context, j *Job) (existing *Job, inserted bool, err error)
	Dequeue(ctx context.Context, workerID string) (*Job, error)
	Complete(ctx context.Context, jobID string) error
	Fail(ctx context.Context, jobID, errMsg string, retry bool) error
}

// SQLQueue is the SQLite-backed (and Postgres-backed) Queue. It delegates to
// store.EnqueuedJobStore for storage, which makes the two solo/teams modes
// share the same code path; the Redis-backed asynq impl is the only other
// option and ships when Compose mode needs throughput across workers.
type SQLQueue struct {
	Jobs store.EnqueuedJobStore
}

// NewSQLQueue wires a Queue to the given store.
func NewSQLQueue(jobs store.EnqueuedJobStore) *SQLQueue { return &SQLQueue{Jobs: jobs} }

// Enqueue persists the job (or no-ops on idempotency-key conflict).
func (q *SQLQueue) Enqueue(ctx context.Context, j *Job) (*Job, bool, error) {
	row := &store.EnqueuedJob{
		ID:             j.ID,
		JobType:        j.Type,
		PayloadJSON:    j.PayloadJSON,
		IdempotencyKey: j.IdempotencyKey,
		Attempts:       j.Attempts,
		RunAfter:       j.RunAfter,
	}
	existing, inserted, err := q.Jobs.Enqueue(ctx, row)
	if err != nil {
		return nil, false, err
	}
	return jobFromRow(existing), inserted, nil
}

// Dequeue atomically claims the next pending job.
func (q *SQLQueue) Dequeue(ctx context.Context, workerID string) (*Job, error) {
	row, err := q.Jobs.Claim(ctx, workerID, time.Now().UTC())
	if err != nil || row == nil {
		return nil, err
	}
	return jobFromRow(row), nil
}

// Complete marks a job done.
func (q *SQLQueue) Complete(ctx context.Context, jobID string) error {
	return q.Jobs.Complete(ctx, jobID)
}

// Fail marks the job failed; when retry is true the job is requeued.
func (q *SQLQueue) Fail(ctx context.Context, jobID, errMsg string, retry bool) error {
	return q.Jobs.Fail(ctx, jobID, errMsg, retry)
}

func jobFromRow(r *store.EnqueuedJob) *Job {
	if r == nil {
		return nil
	}
	return &Job{
		ID:             r.ID,
		Type:           r.JobType,
		PayloadJSON:    r.PayloadJSON,
		IdempotencyKey: r.IdempotencyKey,
		Attempts:       r.Attempts,
		RunAfter:       r.RunAfter,
	}
}
