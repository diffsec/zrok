package tools

import (
	"context"

	"github.com/diffsec/quokka/internal/think"
)

// thinkTool is the shared body for each thinking-verb tool. We mint one
// type per verb to keep registration simple and let agents whitelist by
// granular tool name.
type thinkTool struct {
	verb        think.ThinkingVerb
	toolName    string
	description string
}

func (t *thinkTool) Name() string        { return t.toolName }
func (t *thinkTool) Description() string { return t.description }
func (t *thinkTool) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"context":{"type":"string"}}}`)
}

func (t *thinkTool) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Context string `json:"context"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	res, err := think.Prompt(think.PromptRequest{Verb: t.verb, Context: args.Context})
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}

// ThinkCollected wraps verb=collected.
type ThinkCollected struct{}

func (ThinkCollected) Name() string {
	return (&thinkTool{verb: think.VerbCollected, toolName: "think_collected"}).Name()
}
func (ThinkCollected) Description() string {
	return "Audit the memory store against agents' declared context_memories."
}
func (ThinkCollected) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkCollected) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbCollected, toolName: "think_collected"}).Call(ctx, env, input)
}

type ThinkDone struct{}

func (ThinkDone) Name() string { return "think_done" }
func (ThinkDone) Description() string {
	return "Score how complete the named agent's work is on its declared CWEs and memories."
}
func (ThinkDone) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkDone) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbDone, toolName: "think_done"}).Call(ctx, env, input)
}

type ThinkNext struct{}

func (ThinkNext) Name() string        { return "think_next" }
func (ThinkNext) Description() string { return "Rank the next actions for this run." }
func (ThinkNext) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkNext) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbNext, toolName: "think_next"}).Call(ctx, env, input)
}

type ThinkHypothesis struct{}

func (ThinkHypothesis) Name() string { return "think_hypothesis" }
func (ThinkHypothesis) Description() string {
	return "Emit ranked CWE hypotheses given the project's tech stack and memory content."
}
func (ThinkHypothesis) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkHypothesis) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbHypothesis, toolName: "think_hypothesis"}).Call(ctx, env, input)
}

type ThinkDataflow struct{}

func (ThinkDataflow) Name() string { return "think_dataflow" }
func (ThinkDataflow) Description() string {
	return "Trace candidate source-to-sink chains within a single file."
}
func (ThinkDataflow) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkDataflow) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbDataflow, toolName: "think_dataflow"}).Call(ctx, env, input)
}

type ThinkAdherence struct{}

func (ThinkAdherence) Name() string { return "think_adherence" }
func (ThinkAdherence) Description() string {
	return "Verify the agent's findings fall within its declared CWE scope."
}
func (ThinkAdherence) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkAdherence) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbAdherence, toolName: "think_adherence"}).Call(ctx, env, input)
}

type ThinkValidate struct{}

func (ThinkValidate) Name() string { return "think_validate" }
func (ThinkValidate) Description() string {
	return "Validate one finding by reading the cited file and surrounding context."
}
func (ThinkValidate) InputSchema() []byte { return (&thinkTool{}).InputSchema() }
func (ThinkValidate) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	return (&thinkTool{verb: think.VerbValidate, toolName: "think_validate"}).Call(ctx, env, input)
}
