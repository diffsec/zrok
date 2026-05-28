package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type sessionStore struct{ db *sql.DB }

func (s *sessionStore) Create(ctx context.Context, sess *store.Session) error {
	if sess.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		sess.ID = id.String()
	}
	now := time.Now().UTC()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	sess.LastSeenAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(id,user_id,created_at,expires_at,last_seen_at,ip,user_agent)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		sess.ID, sess.UserID, sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt, nullStr(sess.IP), nullStr(sess.UserAgent))
	return err
}

func (s *sessionStore) Get(ctx context.Context, id string) (*store.Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,created_at,expires_at,last_seen_at,COALESCE(ip,''),COALESCE(user_agent,'') FROM sessions WHERE id=$1`, id)
	sess := &store.Session{}
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt, &sess.IP, &sess.UserAgent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return sess, nil
}

func (s *sessionStore) Touch(ctx context.Context, id string, lastSeen, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at=$1, expires_at=$2 WHERE id=$3`, lastSeen, expiresAt, id)
	return err
}

func (s *sessionStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=$1`, id)
	return err
}

func (s *sessionStore) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
