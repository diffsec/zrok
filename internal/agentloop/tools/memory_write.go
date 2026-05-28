package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/memory"
)

type MemoryWrite struct{}

func (MemoryWrite) Name() string { return "memory_write" }
func (MemoryWrite) Description() string {
	return "Persist a named memory (context, pattern, or stack) for later recall."
}
func (MemoryWrite) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"name":{"type":"string"},"type":{"type":"string","enum":["context","pattern","stack"]},"content":{"type":"string"},"description":{"type":"string"},"tags":{"type":"array","items":{"type":"string"}}},"required":["name","content"]}`)
}

func (MemoryWrite) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Name        string   `json:"name"`
		Type        string   `json:"type"`
		Content     string   `json:"content"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Memories == nil {
		return "", fmt.Errorf("memory_write: memory store not configured")
	}
	m, err := memory.Write(ctx, env.Stores.Memories, memory.WriteRequest{
		RepoID:      env.RepoID,
		Name:        args.Name,
		Type:        memory.MemoryType(args.Type),
		Content:     args.Content,
		Description: args.Description,
		Tags:        args.Tags,
		CreatedBy:   env.AgentName,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(m), nil
}
