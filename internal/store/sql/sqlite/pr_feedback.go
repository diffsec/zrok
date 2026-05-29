package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

type prFeedbackStore struct{ db *sql.DB }

func (s *prFeedbackStore) Get(ctx context.Context, repoID string) (*store.PRFeedbackSettings, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT repo_id,check_run_enabled,inline_comments_enabled,summary_comment_enabled,inline_severity_threshold,updated_at
		 FROM pr_feedback_settings WHERE repo_id=?`, repoID)
	out := &store.PRFeedbackSettings{}
	var cr, ic, sc int
	if err := row.Scan(&out.RepoID, &cr, &ic, &sc, &out.InlineSeverityThreshold, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	out.CheckRunEnabled = cr != 0
	out.InlineCommentsEnabled = ic != 0
	out.SummaryCommentEnabled = sc != 0
	return out, nil
}

func (s *prFeedbackStore) Upsert(ctx context.Context, p *store.PRFeedbackSettings) error {
	now := time.Now().UTC()
	cr := 0
	if p.CheckRunEnabled {
		cr = 1
	}
	ic := 0
	if p.InlineCommentsEnabled {
		ic = 1
	}
	sc := 0
	if p.SummaryCommentEnabled {
		sc = 1
	}
	thr := p.InlineSeverityThreshold
	if thr == "" {
		thr = "medium"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pr_feedback_settings(repo_id,check_run_enabled,inline_comments_enabled,summary_comment_enabled,inline_severity_threshold,updated_at)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(repo_id) DO UPDATE SET
		   check_run_enabled=excluded.check_run_enabled,
		   inline_comments_enabled=excluded.inline_comments_enabled,
		   summary_comment_enabled=excluded.summary_comment_enabled,
		   inline_severity_threshold=excluded.inline_severity_threshold,
		   updated_at=excluded.updated_at`,
		p.RepoID, cr, ic, sc, thr, now)
	return err
}
