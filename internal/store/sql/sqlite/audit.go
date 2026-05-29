package sqlite

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
		 VALUES(?,?,?,?,?,?,?,?)`,
		id.String(), nullStr(orgID), nullStr(actorID), action,
		nullStr(entity), nullStr(entityID), nullStr(payloadJSON), time.Now().UTC())
	return err
}

