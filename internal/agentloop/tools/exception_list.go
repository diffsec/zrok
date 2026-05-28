package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/exception"
)

type ExceptionList struct{}

func (ExceptionList) Name() string { return "exception_list" }
func (ExceptionList) Description() string {
	return "List active exceptions for the current repo."
}
func (ExceptionList) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"include_expired":{"type":"boolean"}}}`)
}

func (ExceptionList) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		IncludeExpired bool `json:"include_expired"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Exceptions == nil {
		return "", fmt.Errorf("exception_list: exception store not configured")
	}
	res, err := exception.List(ctx, env.Stores.Exceptions, exception.ListRequest{
		RepoID:         env.RepoID,
		IncludeExpired: args.IncludeExpired,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
