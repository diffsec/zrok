package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/navigate"
)

type NavigateRead struct{}

func (NavigateRead) Name() string { return "navigate_read" }
func (NavigateRead) Description() string {
	return "Read a file (optionally a line range) inside the repo sandbox."
}
func (NavigateRead) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"path":{"type":"string"},"line_start":{"type":"integer"},"line_end":{"type":"integer"}},"required":["path"]}`)
}

func (NavigateRead) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Path      string `json:"path"`
		LineStart int    `json:"line_start"`
		LineEnd   int    `json:"line_end"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Project == nil {
		return "", fmt.Errorf("navigate_read: project not set")
	}
	if env.Sandbox != nil {
		if _, ok := env.Sandbox.Resolve(args.Path); !ok {
			return "", ErrEscape
		}
	}
	res, err := navigate.Read(navigate.ReadRequest{
		Project:   env.Project,
		Path:      args.Path,
		LineStart: args.LineStart,
		LineEnd:   args.LineEnd,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
