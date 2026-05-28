package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type auditStore struct{ db *sql.DB }

func (s *auditStore) Append(ctx context.Context, orgID, actorID, action, entity, entityID, payloadJSON string) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO audit_log(id,org_id,actor_id,action,entity,entity_id,payload_json,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		id.String(), nullUUID(orgID), nullUUID(actorID), action,
		nullStr(entity), nullStr(entityID), nullJSON(payloadJSON), time.Now().UTC())
	return err
}

