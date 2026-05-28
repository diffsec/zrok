package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/navigate"
)

type NavigateList struct{}

func (NavigateList) Name() string { return "navigate_list" }
func (NavigateList) Description() string {
	return "List the entries under a directory inside the repo sandbox."
}
func (NavigateList) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"path":{"type":"string"},"max_depth":{"type":"integer"},"recursive":{"type":"boolean"}},"required":["path"]}`)
}

func (NavigateList) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Path      string `json:"path"`
		MaxDepth  int    `json:"max_depth"`
		Recursive bool   `json:"recursive"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Project == nil {
		return "", fmt.Errorf("navigate_list: project not set")
	}
	if env.Sandbox != nil {
		if _, ok := env.Sandbox.Resolve(args.Path); !ok {
			return "", ErrEscape
		}
	}
	res, err := navigate.List(navigate.ListRequest{
		Project: env.Project,
		Path:    args.Path,
		Options: &navigate.ListOptions{MaxDepth: args.MaxDepth, Recursive: args.Recursive},
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
