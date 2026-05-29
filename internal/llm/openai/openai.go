// Package openai implements the llm.Provider interface against the OpenAI
// /v1/chat/completions SSE API. It accepts any OpenAI-compatible upstream
// (OpenAI, OpenRouter, Groq, Together, Ollama with the OpenAI shim, etc.).
package openai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/diffsec/quokka/internal/llm"
)

const providerID = "openai-compat"

func init() {
	llm.Register(providerID, func(c *llm.Config) (llm.Provider, error) {
		return New(c)
	})
}

// Adapter is the OpenAI-compatible implementation of llm.Provider.
type Adapter struct {
	cfg    *llm.Config
	client *http.Client
}

// New constructs an OpenAI-compatible adapter.
func New(c *llm.Config) (*Adapter, error) {
	if c == nil {
		return nil, fmt.Errorf("openai: nil config")
	}
	return &Adapter{cfg: c, client: &http.Client{Timeout: c.Timeout}}, nil
}

// ID implements llm.Provider.
func (a *Adapter) ID() string { return providerID }

// Close implements llm.Provider.
func (a *Adapter) Close() error { return nil }

// Chat implements llm.Provider.
func (a *Adapter) Chat(ctx context.Context, req llm.ChatRequest) (<-chan llm.Event, error) {
	body, err := buildRequest(a.cfg, req)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(a.cfg.BaseURL, "/") + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("accept", "text/event-stream")
	apiKey := a.cfg.APIKey
	if apiKey == "" && a.cfg.APIKeyEnv != "" {
		apiKey = os.Getenv(a.cfg.APIKeyEnv)
	}
	if apiKey != "" {
		httpReq.Header.Set("authorization", "Bearer "+apiKey)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("openai: HTTP %d: %s", resp.StatusCode, string(b))
	}

	ch := make(chan llm.Event, 16)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		ParseSSE(resp.Body, ch)
	}()
	return ch, nil
}

type chatRequest struct {
	Model       string          `json:"model"`
	Messages    []chatMessage   `json:"messages"`
	Tools       []chatTool      `json:"tools,omitempty"`
	Stream      bool            `json:"stream"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float32         `json:"temperature,omitempty"`
	StreamOpt   *streamOpts     `json:"stream_options,omitempty"`
	Stop        []string        `json:"stop,omitempty"`
	Extra       json.RawMessage `json:"-"`
}

type streamOpts struct {
	IncludeUsage bool `json:"include_usage"`
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Name       string         `json:"name,omitempty"`
}

type chatToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function chatToolFunction `json:"function"`
}

type chatToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatTool struct {
	Type     string         `json:"type"`
	Function chatToolFnSpec `json:"function"`
}

type chatToolFnSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

func buildRequest(cfg *llm.Config, req llm.ChatRequest) ([]byte, error) {
	model := req.Model
	if model == "" {
		model = cfg.DefaultModel
	}
	maxTok := req.MaxTokens
	if maxTok == 0 {
		maxTok = cfg.MaxTokens
	}
	temp := req.Temperature
	if temp == 0 {
		temp = cfg.Temperature
	}
	payload := chatRequest{
		Model:       model,
		Stream:      true,
		MaxTokens:   maxTok,
		Temperature: temp,
		Stop:        req.StopSequences,
		StreamOpt:   &streamOpts{IncludeUsage: true},
	}
	if req.System != "" {
		payload.Messages = append(payload.Messages, chatMessage{
			Role:    "system",
			Content: req.System,
		})
	}
	for _, m := range req.Messages {
		// One source Message can fan out to multiple openai messages:
		// text becomes content on an assistant/user message; tool_use
		// becomes assistant.tool_calls; tool_result becomes its own
		// role:"tool" message with tool_call_id.
		var (
			text        strings.Builder
			toolCalls   []chatToolCall
			toolResults []chatMessage
		)
		for _, b := range m.Content {
			switch b.Type {
			case llm.BlockText:
				text.WriteString(b.Text)
			case llm.BlockToolUse:
				input := string(b.ToolInput)
				if input == "" {
					input = "{}"
				}
				toolCalls = append(toolCalls, chatToolCall{
					ID:   b.ToolUseID,
					Type: "function",
					Function: chatToolFunction{
						Name:      b.ToolName,
						Arguments: input,
					},
				})
			case llm.BlockToolResult:
				toolResults = append(toolResults, chatMessage{
					Role:       "tool",
					ToolCallID: b.ToolUseID,
					Content:    b.ToolResult,
				})
			}
		}
		if text.Len() > 0 || len(toolCalls) > 0 {
			msg := chatMessage{Role: m.Role, Content: text.String(), ToolCalls: toolCalls}
			payload.Messages = append(payload.Messages, msg)
		}
		// tool_result blocks always become separate messages.
		payload.Messages = append(payload.Messages, toolResults...)
	}
	for _, t := range req.Tools {
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = []byte(`{"type":"object"}`)
		}
		payload.Tools = append(payload.Tools, chatTool{
			Type: "function",
			Function: chatToolFnSpec{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  schema,
			},
		})
	}
	return json.Marshal(payload)
}

// ParseSSE parses the OpenAI chat-completions SSE stream and emits unified
// Events. The critical job is reassembling fragmented
// tool_calls[i].function.arguments deltas into single tool-use blocks.
func ParseSSE(r io.Reader, out chan<- llm.Event) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8192), 1<<20)

	// Per-index running state for tool calls. Keys are the
	// `tool_calls[*].index` value from the upstream delta.
	type toolState struct {
		id     string
		name   string
		opened bool
	}
	tools := map[int]*toolState{}

	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			// Emit a synthetic end_turn if no stop_reason was sent
			// in a prior chunk's finish_reason field. The loop
			// tolerates an absent stop event by relying on the
			// channel close.
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Role      string `json:"role"`
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		for _, c := range chunk.Choices {
			if c.Delta.Content != "" {
				out <- llm.Event{Kind: llm.EventTextDelta, Text: c.Delta.Content}
			}
			for _, tc := range c.Delta.ToolCalls {
				st, ok := tools[tc.Index]
				if !ok {
					st = &toolState{}
					tools[tc.Index] = st
				}
				if tc.ID != "" {
					st.id = tc.ID
				}
				if tc.Function.Name != "" {
					st.name = tc.Function.Name
				}
				if !st.opened && st.id != "" && st.name != "" {
					st.opened = true
					out <- llm.Event{
						Kind:      llm.EventToolCallStart,
						ToolUseID: st.id,
						ToolName:  st.name,
					}
				}
				if tc.Function.Arguments != "" {
					out <- llm.Event{
						Kind:       llm.EventToolCallDelta,
						ToolUseID:  st.id,
						ToolName:   st.name,
						InputDelta: tc.Function.Arguments,
					}
				}
			}
			if c.FinishReason != "" {
				// Close any open tool blocks before announcing
				// the stop reason.
				for _, st := range tools {
					if st.opened {
						out <- llm.Event{
							Kind:      llm.EventToolCallEnd,
							ToolUseID: st.id,
							ToolName:  st.name,
						}
						st.opened = false
					}
				}
				out <- llm.Event{Kind: llm.EventStopReason, StopReason: normalizeStop(c.FinishReason)}
			}
		}
		if chunk.Usage != nil {
			out <- llm.Event{
				Kind: llm.EventUsageDelta,
				Usage: llm.Usage{
					InputTokens:  chunk.Usage.PromptTokens,
					OutputTokens: chunk.Usage.CompletionTokens,
				},
			}
		}
	}
}

func normalizeStop(s string) string {
	switch s {
	case "stop":
		return llm.StopEndTurn
	case "tool_calls":
		return llm.StopToolUse
	case "length":
		return llm.StopMaxTokens
	default:
		return s
	}
}
