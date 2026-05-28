package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type modelUsageStore struct{ db *sql.DB }

func (s *modelUsageStore) Add(ctx context.Context, u *store.ModelUsage) error {
	day := u.PeriodDay
	now := time.Now().UTC()
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	// ON CONFLICT requires non-null provider_id participation; we model the
	// unique index as (org_id, provider_id, model, period_day) — when
	// provider_id is NULL the conflict won't fire. For PR-4 we always pass
	// the provider_id (when known); a NULL-provider audit row is fine to
	// insert fresh.
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO model_usage(id,org_id,provider_id,model,period_day,input_tokens,output_tokens,cost_micros,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT(org_id, provider_id, model, period_day) DO UPDATE SET
		   input_tokens=model_usage.input_tokens+EXCLUDED.input_tokens,
		   output_tokens=model_usage.output_tokens+EXCLUDED.output_tokens,
		   cost_micros=model_usage.cost_micros+EXCLUDED.cost_micros,
		   updated_at=EXCLUDED.updated_at`,
		id.String(), u.OrgID, nullUUID(u.ProviderID), u.Model, day,
		u.InputTokens, u.OutputTokens, u.CostMicros, now)
	return err
}

func (s *modelUsageStore) ListByDay(ctx context.Context, orgID string, day time.Time) ([]*store.ModelUsage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,org_id,COALESCE(provider_id::text,''),model,period_day,input_tokens,output_tokens,cost_micros,updated_at
		 FROM model_usage WHERE org_id=$1 AND period_day=$2`,
		orgID, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ModelUsage
	for rows.Next() {
		u := &store.ModelUsage{}
		if err := rows.Scan(&u.ID, &u.OrgID, &u.ProviderID, &u.Model, &u.PeriodDay,
			&u.InputTokens, &u.OutputTokens, &u.CostMicros, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

