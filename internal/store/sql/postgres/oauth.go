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

type oauthStore struct {
	db     *sql.DB
	cipher *crypto.Cipher
}

func (s *oauthStore) Upsert(ctx context.Context, t *store.OAuthToken) error {
	if t.UserID == "" || t.Provider == "" {
		return errors.New("oauth: user_id and provider required")
	}
	accessCT, accessIV, ver, err := s.cipher.Encrypt([]byte(t.AccessToken))
	if err != nil {
		return fmt.Errorf("encrypt access_token: %w", err)
	}
	var refreshCT, refreshIV []byte
	if t.RefreshToken != "" {
		refreshCT, refreshIV, _, err = s.cipher.Encrypt([]byte(t.RefreshToken))
		if err != nil {
			return fmt.Errorf("encrypt refresh_token: %w", err)
		}
	}
	now := time.Now().UTC()

	existing, err := s.Get(ctx, t.UserID, t.Provider)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if existing != nil {
		t.ID = existing.ID
		t.CreatedAt = existing.CreatedAt
		t.UpdatedAt = now
		_, err = s.db.ExecContext(ctx,
			`UPDATE oauth_tokens
			   SET access_token_enc=$1, access_token_iv=$2,
			       refresh_token_enc=$3, refresh_token_iv=$4,
			       key_version=$5, scopes=$6, expires_at=$7, updated_at=$8
			 WHERE id=$9`,
			accessCT, accessIV, refreshCT, refreshIV, ver, nullStr(t.Scopes), t.ExpiresAt, now, t.ID)
		return err
	}

	if t.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		t.ID = id.String()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO oauth_tokens(id,user_id,provider,access_token_enc,access_token_iv,refresh_token_enc,refresh_token_iv,key_version,scopes,expires_at,created_at,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		t.ID, t.UserID, t.Provider, accessCT, accessIV, refreshCT, refreshIV, ver, nullStr(t.Scopes), t.ExpiresAt, t.CreatedAt, t.UpdatedAt)
	return err
}

func (s *oauthStore) Get(ctx context.Context, userID, provider string) (*store.OAuthToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,provider,access_token_enc,access_token_iv,refresh_token_enc,refresh_token_iv,key_version,COALESCE(scopes,''),expires_at,created_at,updated_at
		   FROM oauth_tokens WHERE user_id=$1 AND provider=$2`, userID, provider)
	t := &store.OAuthToken{}
	var accessCT, accessIV, refreshCT, refreshIV []byte
	var ver int16
	var expiresAt sql.NullTime
	if err := row.Scan(&t.ID, &t.UserID, &t.Provider, &accessCT, &accessIV, &refreshCT, &refreshIV,
		&ver, &t.Scopes, &expiresAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	accessPT, err := s.cipher.Decrypt(accessCT, accessIV, ver)
	if err != nil {
		return nil, fmt.Errorf("decrypt access_token: %w", err)
	}
	t.AccessToken = string(accessPT)
	if len(refreshCT) > 0 {
		refreshPT, err := s.cipher.Decrypt(refreshCT, refreshIV, ver)
		if err != nil {
			return nil, fmt.Errorf("decrypt refresh_token: %w", err)
		}
		t.RefreshToken = string(refreshPT)
	}
	if expiresAt.Valid {
		ts := expiresAt.Time
		t.ExpiresAt = &ts
	}
	return t, nil
}

func (s *oauthStore) Delete(ctx context.Context, userID, provider string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_tokens WHERE user_id=$1 AND provider=$2`, userID, provider)
	return err
}
