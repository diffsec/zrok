package agent

import (
	"fmt"

	"github.com/diffsec/quokka/internal/project"
)

// ListRequest is the input to List. Project is optional; when supplied the
// list includes any local overrides under .quokka/agents/.
type ListRequest struct {
	Project *project.Project
}

// List returns the merged agent registry (built-ins plus project overrides).
func List(req ListRequest) (*AgentList, error) {
	if req.Project == nil {
		// No project context — return built-ins only.
		agents := GetBuiltinAgents()
		return &AgentList{Agents: agents, Total: len(agents)}, nil
	}
	mgr := NewConfigManager(req.Project, "")
	return mgr.List()
}

// Show returns one agent's full config by name.
func Show(req ListRequest, name string) (*AgentConfig, error) {
	if req.Project == nil {
		if ag := GetBuiltinAgent(name); ag != nil {
			return ag, nil
		}
		return nil, fmt.Errorf("agent %q not found", name)
	}
	mgr := NewConfigManager(req.Project, "")
	return mgr.Get(name)
}

// PromptRequest is the input to Prompt.
type PromptRequest struct {
	Project *project.Project
	Memory  MemoryReader
	Name    string
	Context string
}

// Prompt renders the agent's system prompt with the project's tech stack
// and memory injections baked in.
func Prompt(req PromptRequest) (string, error) {
	cfg, err := Show(ListRequest{Project: req.Project}, req.Name)
	if err != nil {
		return "", err
	}
	g := NewPromptGenerator(req.Project, req.Memory)
	if req.Context != "" {
		return g.GenerateWithContext(cfg, req.Context)
	}
	return g.Generate(cfg)
}

// SuggestRequest is the input to Suggest. Either Classification or Project
// must be set; when both are set Classification wins.
type SuggestRequest struct {
	Project        *project.Project
	Classification project.ProjectClassification
}

// Suggest returns the list of agent names whose applicability rules match
// the given project classification.
func Suggest(req SuggestRequest) ([]string, error) {
	cls := req.Classification
	if req.Project == nil {
		return SuggestAgents(nil, cls), nil
	}
	return SuggestAgents(req.Project, cls), nil
}
