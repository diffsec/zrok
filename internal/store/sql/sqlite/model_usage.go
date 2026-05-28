package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type modelUsageStore struct{ db *sql.DB }

func (s *modelUsageStore) Add(ctx context.Context, u *store.ModelUsage) error {
	day := u.PeriodDay.Format("2006-01-02")
	now := time.Now().UTC()
	// Try to update first; if no row matched, insert a fresh one.
	res, err := s.db.ExecContext(ctx,
		`UPDATE model_usage SET input_tokens=input_tokens+?, output_tokens=output_tokens+?, cost_micros=cost_micros+?, updated_at=?
		 WHERE org_id=? AND COALESCE(provider_id,'')=? AND model=? AND period_day=?`,
		u.InputTokens, u.OutputTokens, u.CostMicros, now,
		u.OrgID, u.ProviderID, u.Model, day)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		return nil
	}
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO model_usage(id,org_id,provider_id,model,period_day,input_tokens,output_tokens,cost_micros,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		id.String(), u.OrgID, nullStr(u.ProviderID), u.Model, day,
		u.InputTokens, u.OutputTokens, u.CostMicros, now)
	return err
}

func (s *modelUsageStore) ListByDay(ctx context.Context, orgID string, day time.Time) ([]*store.ModelUsage, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,org_id,COALESCE(provider_id,''),model,period_day,input_tokens,output_tokens,cost_micros,updated_at
		 FROM model_usage WHERE org_id=? AND period_day=?`,
		orgID, day.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ModelUsage
	for rows.Next() {
		u := &store.ModelUsage{}
		var periodDay string
		if err := rows.Scan(&u.ID, &u.OrgID, &u.ProviderID, &u.Model, &periodDay,
			&u.InputTokens, &u.OutputTokens, &u.CostMicros, &u.UpdatedAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse("2006-01-02", periodDay); err == nil {
			u.PeriodDay = t
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

