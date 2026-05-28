// Package finding's operations.go exposes the pure-Go business functions
// the SaaS tool registry and HTTP handlers call. They take explicit request
// structs and the store.FindingStore interface — no global state, no
// os.Stdout writes, no cobra.
package finding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

// CreateRequest is the input to Create. RepoID, Title, Severity, File,
// LineStart, CreatedBy are required. Fingerprint is recomputed from the
// finding shape so callers can leave it blank.
type CreateRequest struct {
	RepoID         string
	RunID          string
	Title          string
	Severity       Severity
	Confidence     Confidence
	Exploitability Exploitability
	FixPriority    FixPriority
	Status         Status
	CWE            string
	CVSS           *CVSS
	Location       Location
	Description    string
	Impact         string
	Remediation    string
	Evidence       []Evidence
	FlowTrace      *FlowTrace
	References     []string
	Tags           []string
	CreatedBy      string
}

// CreateResult contains the persisted finding row. Deduped is true when
// the call matched an existing (repo, fingerprint, creator) row and
// returned that one rather than inserting a new row.
type CreateResult struct {
	Finding *Finding
	Deduped bool
}

// Create validates the request, computes the fingerprint, and writes a new
// finding (or returns the existing row on a (fingerprint, creator) match).
// Mirrors the legacy YAML store's per-creator dedupe semantics.
func Create(ctx context.Context, fs store.FindingStore, req CreateRequest) (*CreateResult, error) {
	f := &Finding{
		Title:          req.Title,
		Severity:       req.Severity,
		Confidence:     req.Confidence,
		Exploitability: req.Exploitability,
		FixPriority:    req.FixPriority,
		Status:         req.Status,
		CWE:            req.CWE,
		CVSS:           req.CVSS,
		Location:       req.Location,
		Description:    req.Description,
		Impact:         req.Impact,
		Remediation:    req.Remediation,
		Evidence:       req.Evidence,
		FlowTrace:      req.FlowTrace,
		References:     req.References,
		Tags:           req.Tags,
		CreatedBy:      req.CreatedBy,
	}
	if err := Validate(f); err != nil {
		return nil, err
	}
	f.Fingerprint = Fingerprint(*f)

	// Per-creator dedup: same (repo, fingerprint, creator) returns the
	// existing row rather than inserting a duplicate.
	if f.CreatedBy != "" {
		existing, err := fs.FindByFingerprintAndCreator(ctx, req.RepoID, f.Fingerprint, f.CreatedBy)
		if err == nil && existing != nil {
			out := rowToFinding(existing)
			return &CreateResult{Finding: out, Deduped: true}, nil
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("dedup lookup: %w", err)
		}
	}

	row, err := findingToRow(f, req.RepoID, req.RunID)
	if err != nil {
		return nil, err
	}
	if err := fs.Create(ctx, row); err != nil {
		return nil, err
	}
	return &CreateResult{Finding: rowToFinding(row)}, nil
}

// ListRequest filters a List call. Empty fields are wildcards.
type ListRequest struct {
	RepoID         string
	Severity       Severity
	Status         Status
	Confidence     Confidence
	Exploitability Exploitability
	FixPriority    FixPriority
	CWE            string
	File           string
	Tag            string
	CreatedBy      string
}

// List returns the matching findings, sorted by severity desc / created_at desc.
func List(ctx context.Context, fs store.FindingStore, req ListRequest) (*FindingList, error) {
	rows, err := fs.List(ctx, req.RepoID)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(rows))
	for _, r := range rows {
		f := rowToFinding(r)
		if req.Severity != "" && f.Severity != req.Severity {
			continue
		}
		if req.Status != "" && f.Status != req.Status {
			continue
		}
		if req.Confidence != "" && f.Confidence != req.Confidence {
			continue
		}
		if req.Exploitability != "" && f.Exploitability != req.Exploitability {
			continue
		}
		if req.FixPriority != "" && f.FixPriority != req.FixPriority {
			continue
		}
		if req.CWE != "" && !strings.EqualFold(f.CWE, req.CWE) {
			continue
		}
		if req.File != "" && f.Location.File != req.File {
			continue
		}
		if req.CreatedBy != "" && f.CreatedBy != req.CreatedBy {
			continue
		}
		if req.Tag != "" && !containsTag(f.Tags, req.Tag) {
			continue
		}
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool {
		wi := SeverityWeight(out[i].Severity)
		wj := SeverityWeight(out[j].Severity)
		if wi != wj {
			return wi > wj
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return &FindingList{Findings: out, Total: len(out)}, nil
}

// Show fetches a single finding by ID.
func Show(ctx context.Context, fs store.FindingStore, id string) (*Finding, error) {
	row, err := fs.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return rowToFinding(row), nil
}

// UpdateNoteRequest appends a single note to a finding.
type UpdateNoteRequest struct {
	ID     string
	Author string
	Text   string
}

// UpdateNote appends a timestamped note to a finding's notes slice.
func UpdateNote(ctx context.Context, fs store.FindingStore, req UpdateNoteRequest) (*Finding, error) {
	if strings.TrimSpace(req.Text) == "" {
		return nil, errors.New("note text is required")
	}
	row, err := fs.Get(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	f := rowToFinding(row)
	author := req.Author
	if author == "" {
		author = "user"
	}
	f.Notes = append(f.Notes, FindingNote{
		Timestamp: time.Now(),
		Author:    author,
		Text:      req.Text,
	})
	updated, err := findingToRow(f, row.RepoID, row.RunID)
	if err != nil {
		return nil, err
	}
	updated.ID = row.ID
	updated.CreatedAt = row.CreatedAt
	if err := fs.Update(ctx, updated); err != nil {
		return nil, err
	}
	return rowToFinding(updated), nil
}

// TriagePlan is the on-disk shape produced by a triage agent and consumed
// by Triage. Captures status / severity / duplicate-of / note overrides
// for batch updates.
type TriagePlan struct {
	Version   int              `json:"version"`
	Author    string           `json:"author"`
	Decisions []TriageDecision `json:"decisions"`
}

// TriageDecision is one finding's worth of updates inside a TriagePlan.
type TriageDecision struct {
	FindingID          string `json:"finding_id"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	DuplicateOf        string `json:"duplicate_of,omitempty"`
	SeverityOverride   string `json:"severity_override,omitempty"`
	FixPriority        string `json:"fix_priority,omitempty"`
	Exploitability     string `json:"exploitability,omitempty"`
	ConfidenceOverride string `json:"confidence_override,omitempty"`
}

// TriageResult is the per-finding outcome of a Triage call.
type TriageResult struct {
	Applied         int
	Skipped         int
	Errored         int
	StatusBreakdown map[string]int
	Errors          []string
}

// Triage applies a TriagePlan. Each decision is applied independently;
// per-decision failures are counted but do not abort the batch.
func Triage(ctx context.Context, fs store.FindingStore, plan TriagePlan) (*TriageResult, error) {
	if plan.Version != 0 && plan.Version != 1 {
		return nil, fmt.Errorf("unsupported triage plan version: %d", plan.Version)
	}
	author := plan.Author
	if author == "" {
		author = "triage"
	}
	res := &TriageResult{StatusBreakdown: map[string]int{}}
	for _, d := range plan.Decisions {
		if d.FindingID == "" {
			res.Errored++
			res.Errors = append(res.Errors, "decision has no finding_id")
			continue
		}
		row, err := fs.Get(ctx, d.FindingID)
		if err != nil {
			res.Skipped++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", d.FindingID, err))
			continue
		}
		if d.Status != "" && !IsValidStatus(Status(d.Status)) {
			res.Errored++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: invalid status %q", d.FindingID, d.Status))
			continue
		}
		f := rowToFinding(row)
		if d.Status != "" {
			f.Status = Status(d.Status)
			res.StatusBreakdown[d.Status]++
		}
		if d.DuplicateOf != "" {
			f.DuplicateOf = d.DuplicateOf
		}
		if d.SeverityOverride != "" {
			f.Severity = Severity(d.SeverityOverride)
		}
		if d.FixPriority != "" {
			f.FixPriority = FixPriority(d.FixPriority)
		}
		if d.Exploitability != "" {
			f.Exploitability = Exploitability(d.Exploitability)
		}
		if d.ConfidenceOverride != "" {
			f.Confidence = Confidence(d.ConfidenceOverride)
		}
		if d.Reason != "" {
			f.Notes = append(f.Notes, FindingNote{
				Timestamp: time.Now(), Author: author, Text: d.Reason,
			})
		}
		updated, err := findingToRow(f, row.RepoID, row.RunID)
		if err != nil {
			res.Errored++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: encode: %v", d.FindingID, err))
			continue
		}
		updated.ID = row.ID
		updated.CreatedAt = row.CreatedAt
		if err := fs.Update(ctx, updated); err != nil {
			res.Errored++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: update: %v", d.FindingID, err))
			continue
		}
		res.Applied++
	}
	return res, nil
}

// ---- helpers ----

// Validate runs the same checks the legacy YAML store ran on Create. CWE is
// not strictly required (matches legacy behavior) but recommended.
func Validate(f *Finding) error {
	if f.Title == "" {
		return errors.New("title is required")
	}
	if f.Severity != "" {
		f.Severity = Severity(strings.ToLower(string(f.Severity)))
		if !IsValidSeverity(f.Severity) {
			return fmt.Errorf("invalid severity: %s", f.Severity)
		}
	}
	if f.Confidence == "" {
		f.Confidence = ConfidenceMedium
	} else {
		f.Confidence = Confidence(strings.ToLower(string(f.Confidence)))
		if !IsValidConfidence(f.Confidence) {
			return fmt.Errorf("invalid confidence: %s", f.Confidence)
		}
	}
	if f.Status == "" {
		f.Status = StatusOpen
	} else if !IsValidStatus(f.Status) {
		return fmt.Errorf("invalid status: %s", f.Status)
	}
	if f.Exploitability != "" && !IsValidExploitability(f.Exploitability) {
		return fmt.Errorf("invalid exploitability: %s", f.Exploitability)
	}
	if f.FixPriority != "" && !IsValidFixPriority(f.FixPriority) {
		return fmt.Errorf("invalid fix_priority: %s", f.FixPriority)
	}
	if f.Location.File == "" {
		return errors.New("location.file is required")
	}
	if f.Location.LineStart < 1 {
		return fmt.Errorf("location.line_start must be >= 1, got %d", f.Location.LineStart)
	}
	return nil
}

func containsTag(tags []string, tag string) bool {
	tag = strings.ToLower(tag)
	for _, t := range tags {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}

// findingToRow encodes a Finding into the storage row shape. JSON-encoded
// columns (evidence, flow_trace, refs, tags, notes) are marshalled here so
// callers don't need to know the column layout.
func findingToRow(f *Finding, repoID, runID string) (*store.FindingRow, error) {
	row := &store.FindingRow{
		RepoID:         repoID,
		RunID:          runID,
		Fingerprint:    f.Fingerprint,
		Title:          f.Title,
		Severity:       string(f.Severity),
		Confidence:     string(f.Confidence),
		Exploitability: string(f.Exploitability),
		FixPriority:    string(f.FixPriority),
		Status:         string(f.Status),
		CWE:            f.CWE,
		File:           f.Location.File,
		LineStart:      f.Location.LineStart,
		LineEnd:        f.Location.LineEnd,
		FunctionName:   f.Location.Function,
		Snippet:        f.Location.Snippet,
		Description:    f.Description,
		Impact:         f.Impact,
		Remediation:    f.Remediation,
		DuplicateOf:    f.DuplicateOf,
		CreatedBy:      f.CreatedBy,
	}
	if f.CVSS != nil {
		row.CVSSScore = f.CVSS.Score
		row.CVSSVector = f.CVSS.Vector
	}
	for _, encoded := range []struct {
		field *string
		val   any
	}{
		{&row.EvidenceJSON, f.Evidence},
		{&row.FlowTraceJSON, f.FlowTrace},
		{&row.RefsJSON, f.References},
		{&row.TagsJSON, f.Tags},
		{&row.NotesJSON, f.Notes},
	} {
		if isEmpty(encoded.val) {
			continue
		}
		b, err := json.Marshal(encoded.val)
		if err != nil {
			return nil, fmt.Errorf("encode field: %w", err)
		}
		*encoded.field = string(b)
	}
	return row, nil
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []Evidence:
		return len(x) == 0
	case *FlowTrace:
		return x == nil
	case []string:
		return len(x) == 0
	case []FindingNote:
		return len(x) == 0
	}
	return false
}

// rowToFinding decodes a storage row back into a Finding value.
func rowToFinding(row *store.FindingRow) *Finding {
	f := &Finding{
		ID:             row.ID,
		Fingerprint:    row.Fingerprint,
		Title:          row.Title,
		Severity:       Severity(row.Severity),
		Confidence:     Confidence(row.Confidence),
		Exploitability: Exploitability(row.Exploitability),
		FixPriority:    FixPriority(row.FixPriority),
		Status:         Status(row.Status),
		CWE:            row.CWE,
		Location: Location{
			File:      row.File,
			LineStart: row.LineStart,
			LineEnd:   row.LineEnd,
			Function:  row.FunctionName,
			Snippet:   row.Snippet,
		},
		Description: row.Description,
		Impact:      row.Impact,
		Remediation: row.Remediation,
		DuplicateOf: row.DuplicateOf,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
		CreatedBy:   row.CreatedBy,
	}
	if row.CVSSScore != 0 || row.CVSSVector != "" {
		f.CVSS = &CVSS{Score: row.CVSSScore, Vector: row.CVSSVector}
	}
	if row.EvidenceJSON != "" {
		_ = json.Unmarshal([]byte(row.EvidenceJSON), &f.Evidence)
	}
	if row.FlowTraceJSON != "" {
		var ft FlowTrace
		if json.Unmarshal([]byte(row.FlowTraceJSON), &ft) == nil {
			f.FlowTrace = &ft
		}
	}
	if row.RefsJSON != "" {
		_ = json.Unmarshal([]byte(row.RefsJSON), &f.References)
	}
	if row.TagsJSON != "" {
		_ = json.Unmarshal([]byte(row.TagsJSON), &f.Tags)
	}
	if row.NotesJSON != "" {
		_ = json.Unmarshal([]byte(row.NotesJSON), &f.Notes)
	}
	return f
}
