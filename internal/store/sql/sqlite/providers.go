package sqlite

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
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.OrgID, p.Name, p.Protocol, p.BaseURL, nullStr(p.Preset),
		ct, iv, ver, boolToInt(p.IsDefault), p.CreatedAt, p.UpdatedAt)
	return err
}

func (s *providerStore) Get(ctx context.Context, id string) (*store.Provider, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,org_id,name,protocol,base_url,preset,api_key_enc,api_key_iv,key_version,is_default,created_at,updated_at
		   FROM providers WHERE id=?`, id)
	return s.scanProvider(row.Scan)
}

func (s *providerStore) List(ctx context.Context, orgID string) ([]*store.Provider, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,org_id,name,protocol,base_url,preset,api_key_enc,api_key_iv,key_version,is_default,created_at,updated_at
		   FROM providers WHERE org_id=? ORDER BY name`, orgID)
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
		`UPDATE providers SET name=?,protocol=?,base_url=?,preset=?,api_key_enc=?,api_key_iv=?,key_version=?,is_default=?,updated_at=?
		   WHERE id=?`,
		p.Name, p.Protocol, p.BaseURL, nullStr(p.Preset), ct, iv, ver, boolToInt(p.IsDefault), p.UpdatedAt, p.ID)
	return err
}

func (s *providerStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM providers WHERE id=?`, id)
	return err
}

// RotateKeys decrypts every row that does not match the current key_version
// using the keyring (which transparently picks the legacy slot for v0) and
// re-encrypts with the current key.
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
			`UPDATE providers SET api_key_enc=?, api_key_iv=?, key_version=?, updated_at=? WHERE id=?`,
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
	var preset sql.NullString
	var isDefault int
	if err := scan(&p.ID, &p.OrgID, &p.Name, &p.Protocol, &p.BaseURL, &preset, &ct, &iv, &ver,
		&isDefault, &p.CreatedAt, &p.UpdatedAt); err != nil {
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
	if preset.Valid {
		p.Preset = preset.String
	}
	p.IsDefault = isDefault != 0
	return p, nil
}

func nullStr(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
