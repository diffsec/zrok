package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/semantic"
)

type SemanticSearch struct{}

func (SemanticSearch) Name() string { return "semantic_search" }
func (SemanticSearch) Description() string {
	return "Natural-language search over the repo's semantic index."
}
func (SemanticSearch) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"},"multi_hop":{"type":"boolean"}},"required":["query"]}`)
}

func (SemanticSearch) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Query    string `json:"query"`
		Limit    int    `json:"limit"`
		MultiHop bool   `json:"multi_hop"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.VectorStore == nil || env.Embedder == nil {
		return "", fmt.Errorf("semantic_search: semantic index is not enabled for this repo")
	}
	res, err := semantic.Search(ctx, semantic.SearchRequest{
		Store:    env.VectorStore,
		Provider: env.Embedder,
		Query:    args.Query,
		Options:  &semantic.SearchOptions{Limit: args.Limit, MultiHop: args.MultiHop},
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
