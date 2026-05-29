package sqlite

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
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(provider_id,model) DO UPDATE SET
		   display_name=excluded.display_name,
		   context_window=excluded.context_window,
		   input_price_per_mtok=excluded.input_price_per_mtok,
		   output_price_per_mtok=excluded.output_price_per_mtok,
		   metadata_json=excluded.metadata_json,
		   discovered_at=excluded.discovered_at`,
		m.ID, m.ProviderID, m.Model, nullStr(m.DisplayName), m.ContextWindow,
		m.InputPricePerMTok, m.OutputPricePerMTok, nullStr(m.MetadataJSON), m.DiscoveredAt)
	return err
}

func (s *providerModelStore) List(ctx context.Context, providerID string) ([]*store.ProviderModel, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,provider_id,model,COALESCE(display_name,''),COALESCE(context_window,0),
		   COALESCE(input_price_per_mtok,0),COALESCE(output_price_per_mtok,0),
		   COALESCE(metadata_json,''),discovered_at
		 FROM provider_models WHERE provider_id=? ORDER BY model`, providerID)
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
	_, err := s.db.ExecContext(ctx, `DELETE FROM provider_models WHERE provider_id=?`, providerID)
	return err
}
