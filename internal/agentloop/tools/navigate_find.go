package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/navigate"
)

type NavigateFind struct{}

func (NavigateFind) Name() string { return "navigate_find" }
func (NavigateFind) Description() string {
	return "Find files matching a glob pattern in the repo."
}
func (NavigateFind) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"pattern":{"type":"string"},"type":{"type":"string","enum":["file","dir",""]},"max_depth":{"type":"integer"}},"required":["pattern"]}`)
}

func (NavigateFind) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Pattern  string `json:"pattern"`
		Type     string `json:"type"`
		MaxDepth int    `json:"max_depth"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Project == nil {
		return "", fmt.Errorf("navigate_find: project not set")
	}
	res, err := navigate.Find(navigate.FindRequest{
		Project: env.Project,
		Pattern: args.Pattern,
		Options: &navigate.FindOptions{Type: args.Type, MaxDepth: args.MaxDepth},
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
