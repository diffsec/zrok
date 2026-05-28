package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/diffsec/quokka/internal/store"
	"github.com/google/uuid"
)

type findingStore struct{ db *sql.DB }

func (s *findingStore) Create(ctx context.Context, f *store.FindingRow) error {
	if f.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		f.ID = id.String()
	}
	now := time.Now().UTC()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.UpdatedAt = now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO findings(id,repo_id,run_id,fingerprint,title,severity,confidence,
		    exploitability,fix_priority,status,cwe,cvss_score,cvss_vector,file,line_start,
		    line_end,function_name,snippet,description,impact,remediation,evidence_json,
		    flow_trace_json,refs_json,tags_json,notes_json,reopened_count,last_resolved_at,
		    duplicate_of,created_by,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, f.RepoID, nullStr(f.RunID), nullStr(f.Fingerprint), f.Title, f.Severity,
		nullStr(f.Confidence), nullStr(f.Exploitability), nullStr(f.FixPriority), f.Status,
		nullStr(f.CWE), f.CVSSScore, nullStr(f.CVSSVector), nullStr(f.File), f.LineStart,
		f.LineEnd, nullStr(f.FunctionName), nullStr(f.Snippet), nullStr(f.Description),
		nullStr(f.Impact), nullStr(f.Remediation), nullStr(f.EvidenceJSON),
		nullStr(f.FlowTraceJSON), nullStr(f.RefsJSON), nullStr(f.TagsJSON),
		nullStr(f.NotesJSON), f.ReopenedCount, nullTime(f.LastResolvedAt),
		nullStr(f.DuplicateOf), f.CreatedBy, f.CreatedAt, f.UpdatedAt)
	return err
}

func (s *findingStore) Get(ctx context.Context, id string) (*store.FindingRow, error) {
	row := s.db.QueryRowContext(ctx, selectFindingSQL+` WHERE id=?`, id)
	return scanFinding(row.Scan)
}

func (s *findingStore) FindByFingerprintAndCreator(ctx context.Context, repoID, fingerprint, createdBy string) (*store.FindingRow, error) {
	if fingerprint == "" || createdBy == "" {
		return nil, store.ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		selectFindingSQL+` WHERE repo_id=? AND fingerprint=? AND created_by=?`,
		repoID, fingerprint, createdBy)
	return scanFinding(row.Scan)
}

func (s *findingStore) List(ctx context.Context, repoID string) ([]*store.FindingRow, error) {
	rows, err := s.db.QueryContext(ctx,
		selectFindingSQL+` WHERE repo_id=? ORDER BY created_at DESC`, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.FindingRow
	for rows.Next() {
		f, err := scanFinding(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *findingStore) Update(ctx context.Context, f *store.FindingRow) error {
	f.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET run_id=?,fingerprint=?,title=?,severity=?,confidence=?,
		    exploitability=?,fix_priority=?,status=?,cwe=?,cvss_score=?,cvss_vector=?,
		    file=?,line_start=?,line_end=?,function_name=?,snippet=?,description=?,
		    impact=?,remediation=?,evidence_json=?,flow_trace_json=?,refs_json=?,
		    tags_json=?,notes_json=?,reopened_count=?,last_resolved_at=?,
		    duplicate_of=?,updated_at=? WHERE id=?`,
		nullStr(f.RunID), nullStr(f.Fingerprint), f.Title, f.Severity,
		nullStr(f.Confidence), nullStr(f.Exploitability), nullStr(f.FixPriority),
		f.Status, nullStr(f.CWE), f.CVSSScore, nullStr(f.CVSSVector),
		nullStr(f.File), f.LineStart, f.LineEnd, nullStr(f.FunctionName),
		nullStr(f.Snippet), nullStr(f.Description), nullStr(f.Impact),
		nullStr(f.Remediation), nullStr(f.EvidenceJSON), nullStr(f.FlowTraceJSON),
		nullStr(f.RefsJSON), nullStr(f.TagsJSON), nullStr(f.NotesJSON),
		f.ReopenedCount, nullTime(f.LastResolvedAt), nullStr(f.DuplicateOf),
		f.UpdatedAt, f.ID)
	return err
}

func (s *findingStore) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status=?, updated_at=? WHERE id=?`,
		status, time.Now().UTC(), id)
	return err
}

func (s *findingStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE id=?`, id)
	return err
}

const selectFindingSQL = `SELECT id,repo_id,COALESCE(run_id,''),COALESCE(fingerprint,''),
    title,severity,COALESCE(confidence,''),COALESCE(exploitability,''),
    COALESCE(fix_priority,''),status,COALESCE(cwe,''),COALESCE(cvss_score,0),
    COALESCE(cvss_vector,''),COALESCE(file,''),COALESCE(line_start,0),
    COALESCE(line_end,0),COALESCE(function_name,''),COALESCE(snippet,''),
    COALESCE(description,''),COALESCE(impact,''),COALESCE(remediation,''),
    COALESCE(evidence_json,''),COALESCE(flow_trace_json,''),COALESCE(refs_json,''),
    COALESCE(tags_json,''),COALESCE(notes_json,''),reopened_count,last_resolved_at,
    COALESCE(duplicate_of,''),created_by,created_at,updated_at
 FROM findings`

func scanFinding(scan func(...any) error) (*store.FindingRow, error) {
	f := &store.FindingRow{}
	var lastResolved sql.NullTime
	if err := scan(&f.ID, &f.RepoID, &f.RunID, &f.Fingerprint, &f.Title, &f.Severity,
		&f.Confidence, &f.Exploitability, &f.FixPriority, &f.Status, &f.CWE,
		&f.CVSSScore, &f.CVSSVector, &f.File, &f.LineStart, &f.LineEnd,
		&f.FunctionName, &f.Snippet, &f.Description, &f.Impact, &f.Remediation,
		&f.EvidenceJSON, &f.FlowTraceJSON, &f.RefsJSON, &f.TagsJSON, &f.NotesJSON,
		&f.ReopenedCount, &lastResolved, &f.DuplicateOf, &f.CreatedBy,
		&f.CreatedAt, &f.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if lastResolved.Valid {
		t := lastResolved.Time
		f.LastResolvedAt = &t
	}
	return f, nil
}

func nullTime(t *time.Time) interface{} {
	if t == nil || t.IsZero() {
		return nil
	}
	return *t
}
