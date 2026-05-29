package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/exception"
	"github.com/diffsec/quokka/internal/finding"
)

type ExceptionMatch struct{}

func (ExceptionMatch) Name() string { return "exception_match" }
func (ExceptionMatch) Description() string {
	return "Check whether an exception suppresses the given finding shape."
}
func (ExceptionMatch) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"fingerprint":{"type":"string"},"file":{"type":"string"},"cwe":{"type":"string"},"agent_name":{"type":"string"}}}`)
}

func (ExceptionMatch) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Fingerprint string `json:"fingerprint"`
		File        string `json:"file"`
		CWE         string `json:"cwe"`
		AgentName   string `json:"agent_name"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Exceptions == nil {
		return "", fmt.Errorf("exception_match: exception store not configured")
	}
	res, err := exception.Match(ctx, env.Stores.Exceptions, env.RepoID, finding.Finding{
		Fingerprint: args.Fingerprint,
		Location:    finding.Location{File: args.File},
		CWE:         args.CWE,
		CreatedBy:   args.AgentName,
	})
	if err != nil {
		return "", err
	}
	if res == nil {
		return encodeJSON(map[string]any{"matched": false}), nil
	}
	return encodeJSON(map[string]any{"matched": true, "exception": res}), nil
}
