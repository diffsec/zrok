// Package agentloop implements the tool-use loop that drives an agent
// through one or more turns against an llm.Provider. It is purposefully
// transport- and storage-agnostic: the Provider is injected, and
// transcript events flow through an EventSink the caller owns.
package agentloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/diffsec/quokka/internal/llm"
)

// Spec is the input to Run.
type Spec struct {
	// RunID is opaque; appears verbatim on every TranscriptEvent.
	RunID string
	// AgentName is the logical name of the agent driving this loop.
	AgentName string

	Provider     llm.Provider
	Model        string
	Temperature  float32
	MaxTokens    int
	SystemPrompt string
	// InitialUser is the user message that kicks off the conversation.
	InitialUser string

	// Tools is the set of tool specs the provider is told about and the
	// caller's ToolHandler can dispatch on.
	Tools       []llm.ToolSpec
	ToolHandler ToolHandler

	// MaxIters caps how many provider round-trips Run will make. 0 means
	// the default (DefaultMaxIters).
	MaxIters int
	// MaxTokensRun caps total tokens spent by this loop across all
	// turns. 0 disables the cap.
	MaxTokensRun int

	// Sink receives transcript events. Optional; a nil Sink drops them.
	Sink EventSink
}

// DefaultMaxIters is applied when Spec.MaxIters is zero.
const DefaultMaxIters = 16

// Result is what Run returns when the loop terminates.
type Result struct {
	Messages   []llm.Message
	Usage      llm.Usage
	IterCount  int
	StopReason string
}

// ToolHandler dispatches a single tool_use block to the underlying tool
// implementation. Implementations are expected to be goroutine-safe;
// however, Run calls them sequentially per-turn.
type ToolHandler interface {
	Call(ctx context.Context, toolName string, input []byte) (result string, isError bool, err error)
}

// ToolHandlerFunc adapts a plain function to ToolHandler.
type ToolHandlerFunc func(ctx context.Context, toolName string, input []byte) (string, bool, error)

// Call implements ToolHandler.
func (f ToolHandlerFunc) Call(ctx context.Context, toolName string, input []byte) (string, bool, error) {
	return f(ctx, toolName, input)
}

// Run drives the tool-use loop to completion (or an error/limit).
func Run(ctx context.Context, spec Spec) (Result, error) {
	if spec.Provider == nil {
		return Result{}, errors.New("agentloop: provider is required")
	}
	if spec.MaxIters <= 0 {
		spec.MaxIters = DefaultMaxIters
	}

	var seq atomic.Int64
	emit := func(kind EventKind, payload any) {
		if spec.Sink == nil {
			return
		}
		spec.Sink.Emit(TranscriptEvent{
			RunID:     spec.RunID,
			AgentName: spec.AgentName,
			Seq:       int(seq.Add(1)),
			Timestamp: time.Now(),
			Kind:      kind,
			Payload:   payload,
		})
	}

	emit(KindAgentStart, map[string]string{"agent": spec.AgentName})
	if spec.InitialUser != "" {
		emit(KindUserMsg, spec.InitialUser)
	}

	messages := []llm.Message{}
	if spec.InitialUser != "" {
		messages = append(messages, llm.Message{
			Role:    llm.RoleUser,
			Content: []llm.ContentBlock{{Type: llm.BlockText, Text: spec.InitialUser}},
		})
	}

	var totalUsage llm.Usage
	var stopReason string

	for iter := 0; iter < spec.MaxIters; iter++ {
		if err := ctx.Err(); err != nil {
			emit(KindError, err.Error())
			return Result{Messages: messages, Usage: totalUsage, IterCount: iter, StopReason: stopReason}, err
		}

		req := llm.ChatRequest{
			Model:       spec.Model,
			System:      spec.SystemPrompt,
			Messages:    messages,
			Tools:       spec.Tools,
			Temperature: spec.Temperature,
			MaxTokens:   spec.MaxTokens,
		}

		events, err := spec.Provider.Chat(ctx, req)
		if err != nil {
			emit(KindError, err.Error())
			return Result{Messages: messages, Usage: totalUsage, IterCount: iter, StopReason: stopReason}, err
		}

		assistant, turnUsage, turnStop, turnErr := drain(ctx, events, emit, spec.AgentName)
		if turnErr != nil {
			return Result{Messages: messages, Usage: totalUsage, IterCount: iter, StopReason: turnStop}, turnErr
		}
		totalUsage = totalUsage.Add(turnUsage)
		stopReason = turnStop

		if turnUsage.InputTokens != 0 || turnUsage.OutputTokens != 0 ||
			turnUsage.CacheReadTokens != 0 || turnUsage.CacheCreationTokens != 0 {
			emit(KindUsage, turnUsage)
		}

		messages = append(messages, assistant)

		if spec.MaxTokensRun > 0 {
			total := totalUsage.InputTokens + totalUsage.OutputTokens
			if total > spec.MaxTokensRun {
				emit(KindBudgetExceeded, map[string]int{"tokens": total, "cap": spec.MaxTokensRun})
				return Result{Messages: messages, Usage: totalUsage, IterCount: iter + 1, StopReason: stopReason}, nil
			}
		}

		toolUses := extractToolUses(assistant)
		if turnStop != llm.StopToolUse && len(toolUses) == 0 {
			return Result{Messages: messages, Usage: totalUsage, IterCount: iter + 1, StopReason: stopReason}, nil
		}

		// Run each tool call sequentially and append the results as a
		// single user message containing tool_result blocks.
		var results []llm.ContentBlock
		for _, tu := range toolUses {
			if err := ctx.Err(); err != nil {
				emit(KindError, err.Error())
				return Result{Messages: messages, Usage: totalUsage, IterCount: iter + 1, StopReason: stopReason}, err
			}
			result, isErr, err := callTool(ctx, spec.ToolHandler, tu)
			emit(KindToolResult, map[string]any{
				"tool_use_id": tu.ToolUseID,
				"tool":        tu.ToolName,
				"is_error":    isErr || err != nil,
				"result":      result,
			})
			if err != nil {
				result = fmt.Sprintf("tool error: %s", err.Error())
				isErr = true
			}
			results = append(results, llm.ContentBlock{
				Type:       llm.BlockToolResult,
				ToolUseID:  tu.ToolUseID,
				ToolResult: result,
				IsError:    isErr,
			})
		}
		messages = append(messages, llm.Message{Role: llm.RoleUser, Content: results})
	}

	emit(KindLoopAbortedMaxIters, map[string]int{"max_iters": spec.MaxIters})
	return Result{Messages: messages, Usage: totalUsage, IterCount: spec.MaxIters, StopReason: stopReason}, nil
}

// drain consumes the Event channel for one turn and assembles the
// assistant Message. The third return is the final stop_reason; the
// fourth is the first fatal error seen.
func drain(ctx context.Context, events <-chan llm.Event, emit func(EventKind, any), agentName string) (llm.Message, llm.Usage, string, error) {
	msg := llm.Message{Role: llm.RoleAssistant}
	var text strings.Builder

	type toolAccum struct {
		id    string
		name  string
		input strings.Builder
	}
	tools := map[string]*toolAccum{}
	var toolOrder []string

	var usage llm.Usage
	var stopReason string

	for {
		select {
		case <-ctx.Done():
			return msg, usage, stopReason, ctx.Err()
		case ev, ok := <-events:
			if !ok {
				goto done
			}
			switch ev.Kind {
			case llm.EventTextDelta:
				text.WriteString(ev.Text)
			case llm.EventToolCallStart:
				tools[ev.ToolUseID] = &toolAccum{id: ev.ToolUseID, name: ev.ToolName}
				toolOrder = append(toolOrder, ev.ToolUseID)
			case llm.EventToolCallDelta:
				ta, ok := tools[ev.ToolUseID]
				if !ok {
					ta = &toolAccum{id: ev.ToolUseID, name: ev.ToolName}
					tools[ev.ToolUseID] = ta
					toolOrder = append(toolOrder, ev.ToolUseID)
				}
				ta.input.WriteString(ev.InputDelta)
			case llm.EventToolCallEnd:
				// nothing — we close on stop_reason
			case llm.EventUsageDelta:
				usage = usage.Add(ev.Usage)
			case llm.EventStopReason:
				stopReason = ev.StopReason
			case llm.EventError:
				if ev.Err != nil {
					return msg, usage, stopReason, ev.Err
				}
			}
		}
	}
done:
	if text.Len() > 0 {
		msg.Content = append(msg.Content, llm.ContentBlock{Type: llm.BlockText, Text: text.String()})
		emit(KindAssistantText, text.String())
	}
	for _, id := range toolOrder {
		ta := tools[id]
		raw := ta.input.String()
		if raw == "" {
			raw = "{}"
		}
		input := []byte(raw)
		if !json.Valid(input) {
			// Pass through the raw bytes; the tool handler can
			// decide. The loop's contract is preserve-and-deliver.
			input = []byte(raw)
		}
		msg.Content = append(msg.Content, llm.ContentBlock{
			Type:      llm.BlockToolUse,
			ToolUseID: ta.id,
			ToolName:  ta.name,
			ToolInput: input,
		})
		emit(KindToolCall, map[string]any{
			"tool_use_id": ta.id,
			"tool":        ta.name,
			"input":       raw,
		})
	}
	return msg, usage, stopReason, nil
}

// extractToolUses returns the tool_use blocks in order from an assistant
// message.
func extractToolUses(m llm.Message) []llm.ContentBlock {
	var out []llm.ContentBlock
	for _, b := range m.Content {
		if b.Type == llm.BlockToolUse {
			out = append(out, b)
		}
	}
	return out
}

// callTool dispatches a single tool_use block to the handler. A nil
// handler is treated as an error result.
func callTool(ctx context.Context, h ToolHandler, tu llm.ContentBlock) (string, bool, error) {
	if h == nil {
		return "no tool handler configured", true, nil
	}
	return h.Call(ctx, tu.ToolName, tu.ToolInput)
}
