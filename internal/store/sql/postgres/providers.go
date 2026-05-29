package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type providerStore struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

func (s *providerStore) Create(ctx context.Context, p *store.Provider) error {
	if p.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		p.ID = id.String()
	}
	ct, iv, ver, err := s.cipher.Encrypt([]byte(p.APIKey))
	if err != nil {
		return fmt.Errorf("encrypt api_key: %w", err)
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO providers(id,org_id,name,protocol,base_url,preset,api_key_enc,api_key_iv,key_version,is_default,created_at,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		p.ID, p.OrgID, p.Name, p.Protocol, p.BaseURL, nullStr(p.Preset),
		ct, iv, ver, p.IsDefault, p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *providerStore) Get(ctx context.Context, id string) (*store.Provider, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,org_id,name,protocol,base_url,COALESCE(preset,''),api_key_enc,api_key_iv,key_version,is_default,created_at,updated_at
		   FROM providers WHERE id=$1`, id)
	return s.scanProvider(row.Scan)
}

func (s *providerStore) List(ctx context.Context, orgID string) ([]*store.Provider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,org_id,name,protocol,base_url,COALESCE(preset,''),api_key_enc,api_key_iv,key_version,is_default,created_at,updated_at
		   FROM providers WHERE org_id=$1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Provider
	for rows.Next() {
		p, err := s.scanProvider(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *providerStore) Update(ctx context.Context, p *store.Provider) error {
	ct, iv, ver, err := s.cipher.Encrypt([]byte(p.APIKey))
	if err != nil {
		return fmt.Errorf("encrypt api_key: %w", err)
	}
	p.UpdatedAt = time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		`UPDATE providers SET name=$1,protocol=$2,base_url=$3,preset=$4,api_key_enc=$5,api_key_iv=$6,key_version=$7,is_default=$8,updated_at=$9
		   WHERE id=$10`,
		p.Name, p.Protocol, p.BaseURL, nullStr(p.Preset), ct, iv, ver, p.IsDefault, p.UpdatedAt, p.ID)
	return err
}

func (s *providerStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, id)
	return err
}

func (s *providerStore) RotateKeys(ctx context.Context) (int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,api_key_enc,api_key_iv,key_version FROM providers`)
	if err != nil {
		return 0, err
	}
	type row struct {
		id  string
		ct  []byte
		iv  []byte
		ver int16
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ct, &r.iv, &r.ver); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	var rotated int64
	for _, r := range pending {
		if r.ver == crypto.CurrentKeyVersion {
			continue
		}
		plain, err := s.cipher.Decrypt(r.ct, r.iv, r.ver)
		if err != nil {
			return rotated, fmt.Errorf("provider %s: decrypt: %w", r.id, err)
		}
		ct, iv, ver, err := s.cipher.Encrypt(plain)
		if err != nil {
			return rotated, fmt.Errorf("provider %s: encrypt: %w", r.id, err)
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE providers SET api_key_enc=$1, api_key_iv=$2, key_version=$3, updated_at=$4 WHERE id=$5`,
			ct, iv, ver, time.Now().UTC(), r.id); err != nil {
			return rotated, err
		}
		rotated++
	}
	return rotated, nil
}

func (s *providerStore) scanProvider(scan func(...any) error) (*store.Provider, error) {
	p := &store.Provider{}
	var ct, iv []byte
	var ver int16
	if err := scan(&p.ID, &p.OrgID, &p.Name, &p.Protocol, &p.BaseURL, &p.Preset, &ct, &iv, &ver,
		&p.IsDefault, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	plain, err := s.cipher.Decrypt(ct, iv, ver)
	if err != nil {
		return nil, fmt.Errorf("decrypt api_key: %w", err)
	}
	p.APIKey = string(plain)
	return p, nil
}
