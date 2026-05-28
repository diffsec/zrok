package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/agentloop"
	"github.com/diffsec/quokka/internal/llm"
)

// SpawnAgent runs a child agent loop synchronously and returns the child's
// final assistant text as the tool result. Used by orchestrator agents
// (and by per-phase fanout in workflows) to delegate work.
type SpawnAgent struct{}

func (SpawnAgent) Name() string { return "spawn_agent" }
func (SpawnAgent) Description() string {
	return "Run a child agent synchronously with the given prompt fragment and return its final text."
}
func (SpawnAgent) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"agent_name":{"type":"string"},"prompt_fragment":{"type":"string"}},"required":["agent_name","prompt_fragment"]}`)
}

func (SpawnAgent) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		AgentName      string `json:"agent_name"`
		PromptFragment string `json:"prompt_fragment"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	res, err := runChild(ctx, env, args.AgentName, args.PromptFragment)
	if err != nil {
		return "", err
	}
	return res, nil
}

// runChild looks up the agent, builds the child Spec, and calls
// agentloop.Run. Returns the assistant's final text concatenation.
func runChild(ctx context.Context, env *Env, name, fragment string) (string, error) {
	if env == nil {
		return "", fmt.Errorf("spawn_agent: env not set")
	}
	lookup := env.AgentLookup
	if lookup == nil {
		lookup = func(n string) (*agent.AgentConfig, error) {
			cfg := agent.GetBuiltinAgent(n)
			if cfg == nil {
				return nil, fmt.Errorf("agent %q not found", n)
			}
			return cfg, nil
		}
	}
	cfg, err := lookup(name)
	if err != nil {
		return "", err
	}
	if env.ProviderFactory == nil {
		return "", fmt.Errorf("spawn_agent: provider factory not set")
	}
	provider, err := env.ProviderFactory(cfg.ModelConfig)
	if err != nil {
		return "", err
	}

	model := env.SpawnDefaults.Model
	temp := env.SpawnDefaults.Temperature
	maxTokens := env.SpawnDefaults.MaxTokens
	if cfg.ModelConfig != nil {
		if cfg.ModelConfig.Model != "" {
			model = cfg.ModelConfig.Model
		}
		if cfg.ModelConfig.Temperature != 0 {
			temp = cfg.ModelConfig.Temperature
		}
		if cfg.ModelConfig.MaxTokens != 0 {
			maxTokens = cfg.ModelConfig.MaxTokens
		}
	}

	// Construct the child Spec. Tools the child can call are the
	// intersection of the global tool set and the child's whitelist.
	registry := Default()
	tools := registry.Allowed(cfg.ToolsAllowed)

	childEnv := *env
	childEnv.AgentName = cfg.Name

	systemPrompt := buildChildSystem(cfg, fragment)

	res, err := agentloop.Run(ctx, agentloop.Spec{
		RunID:        env.RunID,
		AgentName:    cfg.Name,
		Provider:     provider,
		Model:        model,
		Temperature:  temp,
		MaxTokens:    maxTokens,
		SystemPrompt: systemPrompt,
		InitialUser:  fragment,
		Tools:        tools,
		ToolHandler:  registry.Handler(&childEnv),
		MaxIters:     env.SpawnDefaults.MaxIters,
		MaxTokensRun: env.SpawnDefaults.MaxTokensRun,
		Sink:         nil, // child events flow through the parent Sink if the caller wired it that way
	})
	if err != nil {
		return "", err
	}
	return summarizeAssistant(res), nil
}

func buildChildSystem(cfg *agent.AgentConfig, fragment string) string {
	var b strings.Builder
	b.WriteString("You are ")
	b.WriteString(cfg.Name)
	b.WriteString(", a child agent invoked by an orchestrator.\n")
	if cfg.Description != "" {
		b.WriteString(cfg.Description)
		b.WriteString("\n")
	}
	if strings.TrimSpace(fragment) != "" {
		b.WriteString("\nTask: ")
		b.WriteString(fragment)
		b.WriteString("\n")
	}
	return b.String()
}

// summarizeAssistant joins all text blocks from the final assistant
// turns. We grab everything labelled text; tool blocks are summarized as
// "[tool=NAME]" markers so the orchestrator sees what happened.
func summarizeAssistant(res agentloop.Result) string {
	var out strings.Builder
	for _, m := range res.Messages {
		if m.Role != llm.RoleAssistant {
			continue
		}
		for _, b := range m.Content {
			switch b.Type {
			case llm.BlockText:
				if out.Len() > 0 {
					out.WriteString("\n")
				}
				out.WriteString(b.Text)
			case llm.BlockToolUse:
				if out.Len() > 0 {
					out.WriteString("\n")
				}
				fmt.Fprintf(&out, "[tool=%s]", b.ToolName)
			}
		}
	}
	if out.Len() == 0 {
		return "(child agent produced no text)"
	}
	return out.String()
}
