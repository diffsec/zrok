package exception

import (
	"context"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/finding"
	"github.com/diffsec/quokka/internal/store"
)

// AddRequest carries everything Add needs to write a new exception. At
// least one of Fingerprint / PathGlob / CWE / AgentName must be set; the
// XOR rule is fingerprint-vs-the-rest. Reason and ApprovedBy are required.
type AddRequest struct {
	RepoID      string
	Fingerprint string
	PathGlob    string
	CWE         string
	AgentName   string
	Reason      string
	Expires     time.Time
	ApprovedBy  string
	ApprovedFor string
}

// Add validates the request and persists the exception.
func Add(ctx context.Context, es store.ExceptionStore, req AddRequest) (*Exception, error) {
	e := Exception{
		Fingerprint: req.Fingerprint,
		PathGlob:    req.PathGlob,
		CWE:         req.CWE,
		AgentName:   req.AgentName,
		Reason:      req.Reason,
		Expires:     req.Expires,
		ApprovedBy:  req.ApprovedBy,
		ApprovedFor: req.ApprovedFor,
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	row := &store.ExceptionRow{
		RepoID:      req.RepoID,
		Fingerprint: e.Fingerprint,
		PathGlob:    e.PathGlob,
		CWE:         e.CWE,
		AgentName:   e.AgentName,
		Reason:      e.Reason,
		Expires:     e.Expires,
		ApprovedBy:  e.ApprovedBy,
		ApprovedFor: e.ApprovedFor,
	}
	if err := es.Create(ctx, row); err != nil {
		return nil, err
	}
	out := rowToException(row)
	return &out, nil
}

// Remove deletes an exception by ID.
func Remove(ctx context.Context, es store.ExceptionStore, id string) error {
	return es.Delete(ctx, id)
}

// ListRequest filters a List call.
type ListRequest struct {
	RepoID         string
	IncludeExpired bool
}

// List returns the matching exceptions, sorted by created_at desc.
func List(ctx context.Context, es store.ExceptionStore, req ListRequest) ([]Exception, error) {
	rows, err := es.List(ctx, req.RepoID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]Exception, 0, len(rows))
	for _, r := range rows {
		if !req.IncludeExpired && !r.Expires.IsZero() && now.After(r.Expires) {
			continue
		}
		out = append(out, rowToException(r))
	}
	return out, nil
}

// Match returns the first non-expired exception suppressing the given
// finding, or nil when none match.
func Match(ctx context.Context, es store.ExceptionStore, repoID string, f finding.Finding) (*Exception, error) {
	if es == nil {
		return nil, errors.New("exception store is nil")
	}
	row, err := es.Match(ctx, repoID, f.Fingerprint, f.Location.File, f.CWE, f.CreatedBy)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, nil
	}
	out := rowToException(row)
	return &out, nil
}

func rowToException(row *store.ExceptionRow) Exception {
	return Exception{
		ID:          row.ID,
		Fingerprint: row.Fingerprint,
		PathGlob:    row.PathGlob,
		CWE:         row.CWE,
		AgentName:   row.AgentName,
		Reason:      row.Reason,
		Expires:     row.Expires,
		ApprovedBy:  row.ApprovedBy,
		ApprovedFor: row.ApprovedFor,
		CreatedAt:   row.CreatedAt,
	}
}
