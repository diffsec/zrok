package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/memory"
)

type MemoryDelete struct{}

func (MemoryDelete) Name() string { return "memory_delete" }
func (MemoryDelete) Description() string {
	return "Delete a memory by name."
}
func (MemoryDelete) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
}

func (MemoryDelete) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Name string `json:"name"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Memories == nil {
		return "", fmt.Errorf("memory_delete: memory store not configured")
	}
	if err := memory.Delete(ctx, env.Stores.Memories, env.RepoID, args.Name); err != nil {
		return "", err
	}
	return encodeJSON(map[string]string{"deleted": args.Name}), nil
}
