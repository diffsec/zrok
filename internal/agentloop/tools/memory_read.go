package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/memory"
)

type MemoryRead struct{}

func (MemoryRead) Name() string { return "memory_read" }
func (MemoryRead) Description() string {
	return "Read a previously-saved memory by name."
}
func (MemoryRead) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`)
}

func (MemoryRead) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Name string `json:"name"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Memories == nil {
		return "", fmt.Errorf("memory_read: memory store not configured")
	}
	m, err := memory.Read(ctx, env.Stores.Memories, env.RepoID, args.Name)
	if err != nil {
		return "", err
	}
	return encodeJSON(m), nil
}
