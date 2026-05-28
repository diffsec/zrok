package postgres

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
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
		        $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)`,
		f.ID, f.RepoID, nullUUID(f.RunID), nullStr(f.Fingerprint), f.Title, f.Severity,
		nullStr(f.Confidence), nullStr(f.Exploitability), nullStr(f.FixPriority), f.Status,
		nullStr(f.CWE), f.CVSSScore, nullStr(f.CVSSVector), nullStr(f.File), f.LineStart,
		f.LineEnd, nullStr(f.FunctionName), nullStr(f.Snippet), nullStr(f.Description),
		nullStr(f.Impact), nullStr(f.Remediation), nullJSON(f.EvidenceJSON),
		nullJSON(f.FlowTraceJSON), nullJSON(f.RefsJSON), nullJSON(f.TagsJSON),
		nullJSON(f.NotesJSON), f.ReopenedCount, nullTime(f.LastResolvedAt),
		nullUUID(f.DuplicateOf), f.CreatedBy, f.CreatedAt, f.UpdatedAt)
	return err
}

func (s *findingStore) Get(ctx context.Context, id string) (*store.FindingRow, error) {
	row := s.db.QueryRowContext(ctx, selectFindingSQL+` WHERE id=$1`, id)
	return scanFinding(row.Scan)
}

func (s *findingStore) FindByFingerprintAndCreator(ctx context.Context, repoID, fingerprint, createdBy string) (*store.FindingRow, error) {
	if fingerprint == "" || createdBy == "" {
		return nil, store.ErrNotFound
	}
	row := s.db.QueryRowContext(ctx,
		selectFindingSQL+` WHERE repo_id=$1 AND fingerprint=$2 AND created_by=$3`,
		repoID, fingerprint, createdBy)
	return scanFinding(row.Scan)
}

func (s *findingStore) List(ctx context.Context, repoID string) ([]*store.FindingRow, error) {
	rows, err := s.db.QueryContext(ctx,
		selectFindingSQL+` WHERE repo_id=$1 ORDER BY created_at DESC`, repoID)
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
		`UPDATE findings SET run_id=$1,fingerprint=$2,title=$3,severity=$4,confidence=$5,
		    exploitability=$6,fix_priority=$7,status=$8,cwe=$9,cvss_score=$10,cvss_vector=$11,
		    file=$12,line_start=$13,line_end=$14,function_name=$15,snippet=$16,description=$17,
		    impact=$18,remediation=$19,evidence_json=$20,flow_trace_json=$21,refs_json=$22,
		    tags_json=$23,notes_json=$24,reopened_count=$25,last_resolved_at=$26,
		    duplicate_of=$27,updated_at=$28 WHERE id=$29`,
		nullUUID(f.RunID), nullStr(f.Fingerprint), f.Title, f.Severity,
		nullStr(f.Confidence), nullStr(f.Exploitability), nullStr(f.FixPriority),
		f.Status, nullStr(f.CWE), f.CVSSScore, nullStr(f.CVSSVector),
		nullStr(f.File), f.LineStart, f.LineEnd, nullStr(f.FunctionName),
		nullStr(f.Snippet), nullStr(f.Description), nullStr(f.Impact),
		nullStr(f.Remediation), nullJSON(f.EvidenceJSON), nullJSON(f.FlowTraceJSON),
		nullJSON(f.RefsJSON), nullJSON(f.TagsJSON), nullJSON(f.NotesJSON),
		f.ReopenedCount, nullTime(f.LastResolvedAt), nullUUID(f.DuplicateOf),
		f.UpdatedAt, f.ID)
	return err
}

func (s *findingStore) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status=$1, updated_at=$2 WHERE id=$3`,
		status, time.Now().UTC(), id)
	return err
}

func (s *findingStore) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE id=$1`, id)
	return err
}

const selectFindingSQL = `SELECT id,repo_id,COALESCE(run_id::text,''),COALESCE(fingerprint,''),
    title,severity,COALESCE(confidence,''),COALESCE(exploitability,''),
    COALESCE(fix_priority,''),status,COALESCE(cwe,''),COALESCE(cvss_score,0),
    COALESCE(cvss_vector,''),COALESCE(file,''),COALESCE(line_start,0),
    COALESCE(line_end,0),COALESCE(function_name,''),COALESCE(snippet,''),
    COALESCE(description,''),COALESCE(impact,''),COALESCE(remediation,''),
    COALESCE(evidence_json::text,''),COALESCE(flow_trace_json::text,''),
    COALESCE(refs_json::text,''),COALESCE(tags_json::text,''),
    COALESCE(notes_json::text,''),reopened_count,last_resolved_at,
    COALESCE(duplicate_of::text,''),created_by,created_at,updated_at
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

// nullUUID returns nil for empty strings so empty foreign-key UUID columns
// stay NULL rather than failing UUID parse.
func nullUUID(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}

// nullJSON treats empty strings as NULL JSONB. Non-empty values are returned
// as-is so the driver parses them as JSON.
func nullJSON(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}
