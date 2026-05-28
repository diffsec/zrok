package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/navigate"
)

type NavigateSymbols struct{}

func (NavigateSymbols) Name() string { return "navigate_symbols" }
func (NavigateSymbols) Description() string {
	return "Extract symbols from a file or find a named symbol across the repo."
}
func (NavigateSymbols) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"path":{"type":"string"},"name":{"type":"string"}}}`)
}

func (NavigateSymbols) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Project == nil {
		return "", fmt.Errorf("navigate_symbols: project not set")
	}
	if args.Path == "" && args.Name == "" {
		return "", fmt.Errorf("navigate_symbols: either path or name is required")
	}
	res, err := navigate.Symbols(navigate.SymbolsRequest{
		Project: env.Project,
		Path:    args.Path,
		Name:    args.Name,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
