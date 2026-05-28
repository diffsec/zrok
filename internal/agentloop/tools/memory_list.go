package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/memory"
)

type MemoryList struct{}

func (MemoryList) Name() string { return "memory_list" }
func (MemoryList) Description() string {
	return "List memories in the repo, optionally filtered by type."
}
func (MemoryList) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"type":{"type":"string"}}}`)
}

func (MemoryList) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Type string `json:"type"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Memories == nil {
		return "", fmt.Errorf("memory_list: memory store not configured")
	}
	res, err := memory.List(ctx, env.Stores.Memories, memory.ListRequest{
		RepoID: env.RepoID,
		Type:   memory.MemoryType(args.Type),
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
