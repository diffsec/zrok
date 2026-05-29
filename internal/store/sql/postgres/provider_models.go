package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type providerModelStore struct{ db *sql.DB }

func (s *providerModelStore) Upsert(ctx context.Context, m *store.ProviderModel) error {
	if m.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		m.ID = id.String()
	}
	if m.DiscoveredAt.IsZero() {
		m.DiscoveredAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO provider_models(id,provider_id,model,display_name,context_window,input_price_per_mtok,output_price_per_mtok,metadata_json,discovered_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT(provider_id,model) DO UPDATE SET
		   display_name=EXCLUDED.display_name,
		   context_window=EXCLUDED.context_window,
		   input_price_per_mtok=EXCLUDED.input_price_per_mtok,
		   output_price_per_mtok=EXCLUDED.output_price_per_mtok,
		   metadata_json=EXCLUDED.metadata_json,
		   discovered_at=EXCLUDED.discovered_at`,
		m.ID, m.ProviderID, m.Model, nullStr(m.DisplayName), m.ContextWindow,
		m.InputPricePerMTok, m.OutputPricePerMTok, nullJSON(m.MetadataJSON), m.DiscoveredAt)
	return err
}

func (s *providerModelStore) List(ctx context.Context, providerID string) ([]*store.ProviderModel, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,provider_id,model,COALESCE(display_name,''),COALESCE(context_window,0),
		   COALESCE(input_price_per_mtok,0),COALESCE(output_price_per_mtok,0),
		   COALESCE(metadata_json::text,''),discovered_at
		 FROM provider_models WHERE provider_id=$1 ORDER BY model`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ProviderModel
	for rows.Next() {
		m := &store.ProviderModel{}
		if err := rows.Scan(&m.ID, &m.ProviderID, &m.Model, &m.DisplayName,
			&m.ContextWindow, &m.InputPricePerMTok, &m.OutputPricePerMTok,
			&m.MetadataJSON, &m.DiscoveredAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *providerModelStore) DeleteForProvider(ctx context.Context, providerID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM provider_models WHERE provider_id=$1`, providerID)
	return err
}
