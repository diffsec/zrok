package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type findingActionStore struct{ db *sql.DB }

func (s *findingActionStore) Append(ctx context.Context, findingID, action, actorID, reason, payloadJSON string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO finding_actions(id,finding_id,action,actor_id,reason,payload_json,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		id.String(), findingID, action, nullUUID(actorID), nullStr(reason), nullJSON(payloadJSON),
		time.Now().UTC())
	return err
}

func (s *findingActionStore) List(ctx context.Context, findingID string) ([]*store.FindingAction, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,finding_id,action,COALESCE(actor_id::text,''),COALESCE(reason,''),
		    COALESCE(payload_json::text,''),created_at
		 FROM finding_actions WHERE finding_id=$1 ORDER BY created_at`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.FindingAction
	for rows.Next() {
		a := &store.FindingAction{}
		if err := rows.Scan(&a.ID, &a.FindingID, &a.Action, &a.ActorID,
			&a.Reason, &a.PayloadJSON, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
