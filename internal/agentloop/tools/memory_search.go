package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/memory"
)

type MemorySearch struct{}

func (MemorySearch) Name() string { return "memory_search" }
func (MemorySearch) Description() string {
	return "Full-text search over the repo's memories."
}
func (MemorySearch) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`)
}

func (MemorySearch) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Query string `json:"query"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Memories == nil {
		return "", fmt.Errorf("memory_search: memory store not configured")
	}
	res, err := memory.Search(ctx, env.Stores.Memories, env.RepoID, args.Query)
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
