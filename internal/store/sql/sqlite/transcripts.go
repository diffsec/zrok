package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type transcriptStore struct{ db *sql.DB }

func (s *transcriptStore) Put(ctx context.Context, runID, invocationID, agentName, storageURI, sha256 string, byteSize int64) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO transcripts(id,run_id,invocation_id,agent_name,storage_uri,byte_size,sha256,created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		id.String(), runID, nullStr(invocationID), agentName, storageURI, byteSize, nullStr(sha256), time.Now().UTC())
	return err
}

func (s *transcriptStore) List(ctx context.Context, runID string) ([]*store.Transcript, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,run_id,COALESCE(invocation_id,''),agent_name,storage_uri,byte_size,COALESCE(sha256,''),created_at
		 FROM transcripts WHERE run_id=? ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Transcript
	for rows.Next() {
		t := &store.Transcript{}
		if err := rows.Scan(&t.ID, &t.RunID, &t.InvocationID, &t.AgentName,
			&t.StorageURI, &t.ByteSize, &t.SHA256, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *transcriptStore) Get(ctx context.Context, id string) (*store.Transcript, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,run_id,COALESCE(invocation_id,''),agent_name,storage_uri,byte_size,COALESCE(sha256,''),created_at
		 FROM transcripts WHERE id=?`, id)
	t := &store.Transcript{}
	if err := row.Scan(&t.ID, &t.RunID, &t.InvocationID, &t.AgentName,
		&t.StorageURI, &t.ByteSize, &t.SHA256, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return t, nil
}
