package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/semantic"
)

type SemanticRelated struct{}

func (SemanticRelated) Name() string { return "semantic_related" }
func (SemanticRelated) Description() string {
	return "Find code semantically related to the chunks in a given file."
}
func (SemanticRelated) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"file":{"type":"string"},"limit":{"type":"integer"}},"required":["file"]}`)
}

func (SemanticRelated) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		File  string `json:"file"`
		Limit int    `json:"limit"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.VectorStore == nil || env.Embedder == nil {
		return "", fmt.Errorf("semantic_related: semantic index is not enabled for this repo")
	}
	res, err := semantic.Related(ctx, semantic.RelatedRequest{
		Store:    env.VectorStore,
		Provider: env.Embedder,
		File:     args.File,
		Options:  &semantic.SearchOptions{Limit: args.Limit},
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
