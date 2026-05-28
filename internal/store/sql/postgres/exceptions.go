package postgres

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type exceptionStore struct{ db *sql.DB }

func (s *exceptionStore) Create(ctx context.Context, e *store.ExceptionRow) error {
	if err := validateException(e); err != nil {
		return err
	}
	if e.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		e.ID = id.String()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO exceptions(id,repo_id,fingerprint,path_glob,cwe,agent_name,reason,
		    expires,approved_by,approved_for,created_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		e.ID, e.RepoID, nullStr(e.Fingerprint), nullStr(e.PathGlob), nullStr(e.CWE),
		nullStr(e.AgentName), e.Reason, e.Expires, e.ApprovedBy,
		nullStr(e.ApprovedFor), e.CreatedAt)
	return err
}

func (s *exceptionStore) Get(ctx context.Context, id string) (*store.ExceptionRow, error) {
	row := s.db.QueryRowContext(ctx, selectExceptionSQL+` WHERE id=$1`, id)
	return scanException(row.Scan)
}

func (s *exceptionStore) List(ctx context.Context, repoID string) ([]*store.ExceptionRow, error) {
	rows, err := s.db.QueryContext(ctx,
		selectExceptionSQL+` WHERE repo_id=$1 ORDER BY created_at DESC`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ExceptionRow
	for rows.Next() {
		e, err := scanException(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *exceptionStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM exceptions WHERE id=$1`, id)
	return err
}

func (s *exceptionStore) Match(ctx context.Context, repoID, fingerprint, file, cwe, agentName string) (*store.ExceptionRow, error) {
	all, err := s.List(ctx, repoID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, e := range all {
		if !e.Expires.IsZero() && now.After(e.Expires) {
			continue
		}
		if matchException(e, fingerprint, file, cwe, agentName) {
			return e, nil
		}
	}
	return nil, nil
}

const selectExceptionSQL = `SELECT id,repo_id,COALESCE(fingerprint,''),COALESCE(path_glob,''),
    COALESCE(cwe,''),COALESCE(agent_name,''),reason,expires,approved_by,
    COALESCE(approved_for,''),created_at FROM exceptions`

func scanException(scan func(...any) error) (*store.ExceptionRow, error) {
	e := &store.ExceptionRow{}
	if err := scan(&e.ID, &e.RepoID, &e.Fingerprint, &e.PathGlob, &e.CWE,
		&e.AgentName, &e.Reason, &e.Expires, &e.ApprovedBy, &e.ApprovedFor,
		&e.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return e, nil
}

func validateException(e *store.ExceptionRow) error {
	if strings.TrimSpace(e.Reason) == "" {
		return errors.New("exception: reason is required")
	}
	if e.Expires.IsZero() {
		return errors.New("exception: expires is required")
	}
	if strings.TrimSpace(e.ApprovedBy) == "" {
		return errors.New("exception: approved_by is required")
	}
	hasFP := strings.TrimSpace(e.Fingerprint) != ""
	hasPat := strings.TrimSpace(e.PathGlob) != "" ||
		strings.TrimSpace(e.CWE) != "" || strings.TrimSpace(e.AgentName) != ""
	if hasFP && (strings.TrimSpace(e.PathGlob) != "" ||
		strings.TrimSpace(e.CWE) != "" || strings.TrimSpace(e.AgentName) != "") {
		return errors.New("exception: fingerprint is mutually exclusive with path_glob/cwe/agent_name")
	}
	if !hasFP && !hasPat {
		return errors.New("exception: must set fingerprint, or one of path_glob/cwe/agent_name")
	}
	return nil
}

func matchException(e *store.ExceptionRow, fingerprint, file, cwe, agentName string) bool {
	if strings.TrimSpace(e.Fingerprint) != "" {
		return fingerprint != "" && e.Fingerprint == fingerprint
	}
	if e.AgentName != "" && !strings.EqualFold(e.AgentName, agentName) {
		return false
	}
	if e.CWE != "" && !strings.EqualFold(e.CWE, cwe) {
		return false
	}
	if e.PathGlob != "" {
		ok, err := filepath.Match(e.PathGlob, file)
		if err != nil {
			return false
		}
		if !ok {
			ok, _ = filepath.Match(e.PathGlob, filepath.Base(file))
		}
		if !ok {
			return false
		}
	}
	return true
}
