package postgres

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
		 FROM pr_feedback_settings WHERE repo_id=$1`, repoID)
	out := &store.PRFeedbackSettings{}
	if err := row.Scan(&out.RepoID, &out.CheckRunEnabled, &out.InlineCommentsEnabled,
		&out.SummaryCommentEnabled, &out.InlineSeverityThreshold, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return out, nil
}

func (s *prFeedbackStore) Upsert(ctx context.Context, p *store.PRFeedbackSettings) error {
	now := time.Now().UTC()
	thr := p.InlineSeverityThreshold
	if thr == "" {
		thr = "medium"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pr_feedback_settings(repo_id,check_run_enabled,inline_comments_enabled,summary_comment_enabled,inline_severity_threshold,updated_at)
		 VALUES($1,$2,$3,$4,$5,$6)
		 ON CONFLICT(repo_id) DO UPDATE SET
		   check_run_enabled=EXCLUDED.check_run_enabled,
		   inline_comments_enabled=EXCLUDED.inline_comments_enabled,
		   summary_comment_enabled=EXCLUDED.summary_comment_enabled,
		   inline_severity_threshold=EXCLUDED.inline_severity_threshold,
		   updated_at=EXCLUDED.updated_at`,
		p.RepoID, p.CheckRunEnabled, p.InlineCommentsEnabled, p.SummaryCommentEnabled, thr, now)
	return err
}
