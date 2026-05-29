package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/finding"
)

type FindingList struct{}

func (FindingList) Name() string { return "finding_list" }
func (FindingList) Description() string {
	return "List findings in the current repo, optionally filtered."
}
func (FindingList) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"severity":{"type":"string"},"status":{"type":"string"},"cwe":{"type":"string"},"file":{"type":"string"}}}`)
}

func (FindingList) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Severity string `json:"severity"`
		Status   string `json:"status"`
		CWE      string `json:"cwe"`
		File     string `json:"file"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Findings == nil {
		return "", fmt.Errorf("finding_list: finding store not configured")
	}
	res, err := finding.List(ctx, env.Stores.Findings, finding.ListRequest{
		RepoID:   env.RepoID,
		Severity: finding.Severity(args.Severity),
		Status:   finding.Status(args.Status),
		CWE:      args.CWE,
		File:     args.File,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
