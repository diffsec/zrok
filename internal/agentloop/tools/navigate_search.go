package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/navigate"
)

type NavigateSearch struct{}

func (NavigateSearch) Name() string { return "navigate_search" }
func (NavigateSearch) Description() string {
	return "Search file contents (literal or regex) across the repo."
}
func (NavigateSearch) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"pattern":{"type":"string"},"regex":{"type":"boolean"},"ignore_case":{"type":"boolean"},"file_pattern":{"type":"string"},"max_results":{"type":"integer"},"context":{"type":"integer"}},"required":["pattern"]}`)
}

func (NavigateSearch) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Pattern     string `json:"pattern"`
		Regex       bool   `json:"regex"`
		IgnoreCase  bool   `json:"ignore_case"`
		FilePattern string `json:"file_pattern"`
		MaxResults  int    `json:"max_results"`
		Context     int    `json:"context"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Project == nil {
		return "", fmt.Errorf("navigate_search: project not set")
	}
	res, err := navigate.Search(navigate.SearchRequest{
		Project: env.Project,
		Pattern: args.Pattern,
		Options: &navigate.SearchOptions{
			Regex:       args.Regex,
			IgnoreCase:  args.IgnoreCase,
			FilePattern: args.FilePattern,
			MaxResults:  args.MaxResults,
			Context:     args.Context,
		},
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
