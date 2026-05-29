package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/diffsec/quokka/internal/exception"
)

type ExceptionAdd struct{}

func (ExceptionAdd) Name() string { return "exception_add" }
func (ExceptionAdd) Description() string {
	return "Suppress findings by fingerprint or by pattern (path_glob+cwe / cwe / agent_name)."
}
func (ExceptionAdd) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"fingerprint":{"type":"string"},"path_glob":{"type":"string"},"cwe":{"type":"string"},"agent_name":{"type":"string"},"reason":{"type":"string"},"expires":{"type":"string","format":"date-time"},"approved_by":{"type":"string"},"approved_for":{"type":"string"}},"required":["reason","expires","approved_by"]}`)
}

func (ExceptionAdd) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Fingerprint string `json:"fingerprint"`
		PathGlob    string `json:"path_glob"`
		CWE         string `json:"cwe"`
		AgentName   string `json:"agent_name"`
		Reason      string `json:"reason"`
		Expires     string `json:"expires"`
		ApprovedBy  string `json:"approved_by"`
		ApprovedFor string `json:"approved_for"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Exceptions == nil {
		return "", fmt.Errorf("exception_add: exception store not configured")
	}
	exp, err := time.Parse(time.RFC3339, args.Expires)
	if err != nil {
		return "", fmt.Errorf("expires must be RFC3339: %w", err)
	}
	e, err := exception.Add(ctx, env.Stores.Exceptions, exception.AddRequest{
		RepoID:      env.RepoID,
		Fingerprint: args.Fingerprint,
		PathGlob:    args.PathGlob,
		CWE:         args.CWE,
		AgentName:   args.AgentName,
		Reason:      args.Reason,
		Expires:     exp,
		ApprovedBy:  args.ApprovedBy,
		ApprovedFor: args.ApprovedFor,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(e), nil
}
