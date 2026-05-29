package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type webhookLogStore struct{ db *sql.DB }

func (s *webhookLogStore) Append(ctx context.Context, w *store.GitHubWebhookLog) error {
	if w.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		w.ID = id.String()
	}
	if w.ReceivedAt.IsZero() {
		w.ReceivedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO github_webhook_log(id,delivery_id,event_type,action,payload_json,signature,received_at,processed_at,process_error)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(delivery_id) DO NOTHING`,
		w.ID, w.DeliveryID, w.EventType, nullStr(w.Action), w.PayloadJSON,
		nullStr(w.Signature), w.ReceivedAt, w.ProcessedAt, nullStr(w.ProcessError))
	return err
}

func (s *webhookLogStore) Get(ctx context.Context, deliveryID string) (*store.GitHubWebhookLog, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,delivery_id,event_type,COALESCE(action,''),payload_json,COALESCE(signature,''),received_at,processed_at,COALESCE(process_error,'')
		 FROM github_webhook_log WHERE delivery_id=?`, deliveryID)
	w := &store.GitHubWebhookLog{}
	var processed sql.NullTime
	if err := row.Scan(&w.ID, &w.DeliveryID, &w.EventType, &w.Action,
		&w.PayloadJSON, &w.Signature, &w.ReceivedAt, &processed, &w.ProcessError); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if processed.Valid {
		ts := processed.Time
		w.ProcessedAt = &ts
	}
	return w, nil
}

func (s *webhookLogStore) MarkProcessed(ctx context.Context, deliveryID, processError string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE github_webhook_log SET processed_at=?, process_error=? WHERE delivery_id=?`,
		time.Now().UTC(), nullStr(processError), deliveryID)
	return err
}
