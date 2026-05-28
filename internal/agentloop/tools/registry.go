package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/embedding"
	"github.com/diffsec/quokka/internal/llm"
	"github.com/diffsec/quokka/internal/project"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/vectordb"
)

// Env carries the cross-cutting context every tool call needs. Tools
// access only what they require — `memory_write` reaches into Stores.Memories,
// `navigate_*` uses Project + Sandbox, `spawn_agent` uses the AgentLookup +
// ProviderFactory.
type Env struct {
	Project   *project.Project
	Stores    *store.Stores
	Sandbox   *Sandbox
	AgentName string
	RepoID    string
	RunID     string
	CreatedBy string

	// VectorStore and Embedder are set when semantic search is enabled
	// for this repo. Tools that need them check for nil and refuse.
	VectorStore vectordb.Store
	Embedder    embedding.Provider

	// AgentLookup returns the AgentConfig for a named agent. Used by
	// spawn_agent; defaults to agent.GetBuiltinAgent when nil.
	AgentLookup func(name string) (*agent.AgentConfig, error)

	// ProviderFactory builds an llm.Provider for a child agent. Used by
	// spawn_agent. Required when spawn_agent is in the tool set.
	ProviderFactory func(modelCfg *agent.ModelConfig) (llm.Provider, error)

	// SpawnDefaults are applied to child specs when the model config is
	// nil. Required when spawn_agent is in the tool set.
	SpawnDefaults SpawnDefaults

	// FindingSink lets the per_finding workflow expansion observe newly
	// created findings without round-tripping through the store. Nil is
	// fine — the finding still goes to the store.
	FindingSink FindingSink
}

// FindingSink is anything that records a finding-creation event.
type FindingSink interface {
	OnFindingCreated(id, severity, file string, lineStart int)
}

// SpawnDefaults are applied to child agent specs unless the agent itself
// declares a ModelConfig.
type SpawnDefaults struct {
	Model        string
	Temperature  float32
	MaxTokens    int
	MaxIters     int
	MaxTokensRun int
}

// Tool is the per-tool interface. Implementations register themselves
// with a Registry; the Registry's Handler dispatches by name.
type Tool interface {
	Name() string
	Description() string
	InputSchema() []byte
	Call(ctx context.Context, env *Env, input []byte) (string, error)
}

// Registry holds a set of tools keyed by name.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry constructs an empty Registry.
func NewRegistry() *Registry {
	return &Registry{tools: map[string]Tool{}}
}

// Register adds a tool. Replacing an existing tool with the same name is
// silently allowed (tests reset the registry between cases).
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// Get returns the named tool or nil.
func (r *Registry) Get(name string) Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tools[name]
}

// Names returns the registered tool names sorted alphabetically would
// require an allocation; callers don't need ordering today.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.tools))
	for k := range r.tools {
		out = append(out, k)
	}
	return out
}

// Allowed returns the llm.ToolSpec list for the named tools. Names that
// don't resolve are skipped (callers that care can compare lengths).
func (r *Registry) Allowed(names []string) []llm.ToolSpec {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]llm.ToolSpec, 0, len(names))
	for _, n := range names {
		t, ok := r.tools[n]
		if !ok {
			continue
		}
		out = append(out, llm.ToolSpec{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: t.InputSchema(),
		})
	}
	return out
}

// Handler returns an agentloop.ToolHandler that dispatches into the
// registry with the given env. Unknown tools return an is_error=true
// result rather than failing the loop.
func (r *Registry) Handler(env *Env) agentloop.ToolHandler {
	return agentloop.ToolHandlerFunc(func(ctx context.Context, name string, input []byte) (string, bool, error) {
		t := r.Get(name)
		if t == nil {
			return fmt.Sprintf("unknown tool: %s", name), true, nil
		}
		out, err := t.Call(ctx, env, input)
		if err != nil {
			return err.Error(), true, nil
		}
		return out, false, nil
	})
}

// Default builds a registry with every PR-2 tool pre-registered.
func Default() *Registry {
	r := NewRegistry()
	r.Register(&NavigateList{})
	r.Register(&NavigateRead{})
	r.Register(&NavigateFind{})
	r.Register(&NavigateSearch{})
	r.Register(&NavigateSymbols{})
	r.Register(&SemanticSearch{})
	r.Register(&SemanticRelated{})
	r.Register(&MemoryRead{})
	r.Register(&MemoryWrite{})
	r.Register(&MemoryList{})
	r.Register(&MemorySearch{})
	r.Register(&MemoryDelete{})
	r.Register(&FindingCreate{})
	r.Register(&FindingList{})
	r.Register(&FindingShow{})
	r.Register(&FindingUpdateNote{})
	r.Register(&FindingTriage{})
	r.Register(&ExceptionAdd{})
	r.Register(&ExceptionList{})
	r.Register(&ExceptionMatch{})
	r.Register(&ThinkCollected{})
	r.Register(&ThinkDone{})
	r.Register(&ThinkNext{})
	r.Register(&ThinkHypothesis{})
	r.Register(&ThinkDataflow{})
	r.Register(&ThinkAdherence{})
	r.Register(&ThinkValidate{})
	r.Register(&SpawnAgent{})
	r.Register(&SpawnAgentsParallel{})
	return r
}

// decode is the small helper every tool uses to unmarshal its input.
func decode(input []byte, out any) error {
	if len(input) == 0 {
		return nil
	}
	return json.Unmarshal(input, out)
}

// encodeJSON marshals v as a JSON string for tool results. Any error is
// rendered into the result so the agent can see what happened.
func encodeJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(b)
}
