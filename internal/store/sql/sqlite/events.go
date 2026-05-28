package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type eventStore struct{ db *sql.DB }

func (s *eventStore) Append(ctx context.Context, runID, eventType, payloadJSON string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO timeline_events(id,run_id,ts,event_type,payload_json) VALUES(?,?,?,?,?)`,
		id.String(), runID, time.Now().UTC(), eventType, nullStr(payloadJSON))
	return err
}

func (s *eventStore) Stream(ctx context.Context, runID string, sinceTS time.Time) ([]*store.TimelineEvent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,run_id,ts,event_type,COALESCE(payload_json,'') FROM timeline_events
		 WHERE run_id=? AND ts>=? ORDER BY ts, id`,
		runID, sinceTS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.TimelineEvent
	for rows.Next() {
		e := &store.TimelineEvent{}
		if err := rows.Scan(&e.ID, &e.RunID, &e.TS, &e.EventType, &e.PayloadJSON); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

