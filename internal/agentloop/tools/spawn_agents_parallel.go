package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

const defaultParallelism = 4

type SpawnAgentsParallel struct{}

func (SpawnAgentsParallel) Name() string { return "spawn_agents_parallel" }
func (SpawnAgentsParallel) Description() string {
	return "Run several child agents in parallel and return their aggregated summaries."
}
func (SpawnAgentsParallel) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"agents":{"type":"array","items":{"type":"object","properties":{"agent_name":{"type":"string"},"prompt_fragment":{"type":"string"}},"required":["agent_name","prompt_fragment"]}},"max_parallel":{"type":"integer"}},"required":["agents"]}`)
}

func (SpawnAgentsParallel) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Agents []struct {
			AgentName      string `json:"agent_name"`
			PromptFragment string `json:"prompt_fragment"`
		} `json:"agents"`
		MaxParallel int `json:"max_parallel"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if len(args.Agents) == 0 {
		return "", fmt.Errorf("spawn_agents_parallel: at least one agent is required")
	}
	cap := args.MaxParallel
	if cap <= 0 {
		cap = defaultParallelism
	}

	results := make([]string, len(args.Agents))
	sem := make(chan struct{}, cap)
	g, gctx := errgroup.WithContext(ctx)
	var mu sync.Mutex
	for i, spec := range args.Agents {
		i, spec := i, spec
		g.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			defer func() { <-sem }()
			res, err := runChild(gctx, env, spec.AgentName, spec.PromptFragment)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results[i] = fmt.Sprintf("%s ERROR: %s", spec.AgentName, err.Error())
				return nil
			}
			results[i] = fmt.Sprintf("=== %s ===\n%s", spec.AgentName, res)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return "", err
	}
	return strings.Join(results, "\n\n"), nil
}
