package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/finding"
)

type FindingCreate struct{}

func (FindingCreate) Name() string { return "finding_create" }
func (FindingCreate) Description() string {
	return "Create a new security finding for the current repo and run."
}
func (FindingCreate) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"title":{"type":"string"},"severity":{"type":"string"},"confidence":{"type":"string"},"cwe":{"type":"string"},"file":{"type":"string"},"line_start":{"type":"integer"},"line_end":{"type":"integer"},"function":{"type":"string"},"snippet":{"type":"string"},"description":{"type":"string"},"impact":{"type":"string"},"remediation":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}}},"required":["title","severity","file","line_start"]}`)
}

func (FindingCreate) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Title       string   `json:"title"`
		Severity    string   `json:"severity"`
		Confidence  string   `json:"confidence"`
		CWE         string   `json:"cwe"`
		File        string   `json:"file"`
		LineStart   int      `json:"line_start"`
		LineEnd     int      `json:"line_end"`
		Function    string   `json:"function"`
		Snippet     string   `json:"snippet"`
		Description string   `json:"description"`
		Impact      string   `json:"impact"`
		Remediation string   `json:"remediation"`
		Tags        []string `json:"tags"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Findings == nil {
		return "", fmt.Errorf("finding_create: finding store not configured")
	}
	res, err := finding.Create(ctx, env.Stores.Findings, finding.CreateRequest{
		RepoID:     env.RepoID,
		RunID:      env.RunID,
		Title:      args.Title,
		Severity:   finding.Severity(args.Severity),
		Confidence: finding.Confidence(args.Confidence),
		CWE:        args.CWE,
		Location: finding.Location{
			File:      args.File,
			LineStart: args.LineStart,
			LineEnd:   args.LineEnd,
			Function:  args.Function,
			Snippet:   args.Snippet,
		},
		Description: args.Description,
		Impact:      args.Impact,
		Remediation: args.Remediation,
		Tags:        args.Tags,
		CreatedBy:   env.AgentName,
	})
	if err != nil {
		return "", err
	}
	if env.FindingSink != nil && res.Finding != nil {
		env.FindingSink.OnFindingCreated(res.Finding.ID, string(res.Finding.Severity), res.Finding.Location.File, res.Finding.Location.LineStart)
	}
	return encodeJSON(res), nil
}
