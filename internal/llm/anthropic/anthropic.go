// Package anthropic implements the llm.Provider interface against the
// Anthropic /v1/messages SSE API.
package anthropic

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

const providerID = "anthropic"

func init() {
	llm.Register(providerID, func(c *llm.Config) (llm.Provider, error) {
		return New(c)
	})
}

// Adapter is the Anthropic implementation of llm.Provider.
type Adapter struct {
	cfg    *llm.Config
	client *http.Client
}

// New constructs an Anthropic adapter.
func New(c *llm.Config) (*Adapter, error) {
	if c == nil {
		return nil, fmt.Errorf("anthropic: nil config")
	}
	return &Adapter{cfg: c, client: &http.Client{Timeout: c.Timeout}}, nil
}

// ID implements llm.Provider.
func (a *Adapter) ID() string { return providerID }

// Close implements llm.Provider.
func (a *Adapter) Close() error { return nil }

// Chat implements llm.Provider. The returned channel emits unified Events
// parsed from the upstream SSE stream and is closed when the stream ends.
func (a *Adapter) Chat(ctx context.Context, req llm.ChatRequest) (<-chan llm.Event, error) {
	body, err := buildRequest(a.cfg, req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", a.cfg.BaseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("accept", "text/event-stream")
	apiKey := a.cfg.APIKey
	if apiKey == "" && a.cfg.APIKeyEnv != "" {
		apiKey = os.Getenv(a.cfg.APIKeyEnv)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("anthropic: api key not set (env %s)", a.cfg.APIKeyEnv)
	}
	httpReq.Header.Set("x-api-key", apiKey)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, string(b))
	}

	ch := make(chan llm.Event, 16)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		ParseSSE(resp.Body, ch)
	}()
	return ch, nil
}

// requestPayload is the JSON shape POSTed to /v1/messages.
type requestPayload struct {
	Model       string                 `json:"model"`
	System      string                 `json:"system,omitempty"`
	Messages    []anthropicMessage     `json:"messages"`
	Tools       []anthropicTool        `json:"tools,omitempty"`
	Stream      bool                   `json:"stream"`
	MaxTokens   int                    `json:"max_tokens"`
	Temperature float32                `json:"temperature,omitempty"`
	Stop        []string               `json:"stop_sequences,omitempty"`
	Extra       map[string]interface{} `json:"-"`
}

type anthropicMessage struct {
	Role    string             `json:"role"`
	Content []anthropicContent `json:"content"`
}

type anthropicContent struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
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
	payload := requestPayload{
		Model:       model,
		System:      req.System,
		Stream:      true,
		MaxTokens:   maxTok,
		Temperature: temp,
		Stop:        req.StopSequences,
	}
	for _, m := range req.Messages {
		am := anthropicMessage{Role: m.Role}
		for _, b := range m.Content {
			switch b.Type {
			case llm.BlockText:
				am.Content = append(am.Content, anthropicContent{Type: "text", Text: b.Text})
			case llm.BlockToolUse:
				input := json.RawMessage(b.ToolInput)
				if len(input) == 0 {
					input = json.RawMessage("{}")
				}
				am.Content = append(am.Content, anthropicContent{
					Type:  "tool_use",
					ID:    b.ToolUseID,
					Name:  b.ToolName,
					Input: input,
				})
			case llm.BlockToolResult:
				am.Content = append(am.Content, anthropicContent{
					Type:      "tool_result",
					ToolUseID: b.ToolUseID,
					Content:   b.ToolResult,
					IsError:   b.IsError,
				})
			}
		}
		payload.Messages = append(payload.Messages, am)
	}
	for _, t := range req.Tools {
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = []byte(`{"type":"object"}`)
		}
		payload.Tools = append(payload.Tools, anthropicTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schema,
		})
	}
	return json.Marshal(payload)
}

// ParseSSE consumes a Server-Sent Events stream from r and emits unified
// Events to out. The function returns when the stream ends or io fails.
// It is exposed so tests can drive it against fixture bytes.
func ParseSSE(r io.Reader, out chan<- llm.Event) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 8192), 1<<20)

	var eventType string
	var dataLines []string

	// Per-block state. Anthropic SSE emits indexed content blocks; we
	// track the currently-open block by index.
	openBlocks := map[int]*blockState{}

	flush := func() {
		if eventType == "" || len(dataLines) == 0 {
			eventType = ""
			dataLines = nil
			return
		}
		data := strings.Join(dataLines, "\n")
		handleEvent(eventType, data, openBlocks, out)
		eventType = ""
		dataLines = nil
	}

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			continue
		}
	}
	flush()
}

type blockState struct {
	id     string
	name   string
	isTool bool
}

func handleEvent(eventType, data string, blocks map[int]*blockState, out chan<- llm.Event) {
	switch eventType {
	case "message_start":
		// We could surface initial usage here; we only emit usage on
		// message_delta which is when input/output finalize.
	case "content_block_start":
		var payload struct {
			Index        int `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
				Text string `json:"text"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			return
		}
		bs := &blockState{}
		if payload.ContentBlock.Type == "tool_use" {
			bs.isTool = true
			bs.id = payload.ContentBlock.ID
			bs.name = payload.ContentBlock.Name
			blocks[payload.Index] = bs
			out <- llm.Event{
				Kind:      llm.EventToolCallStart,
				ToolUseID: bs.id,
				ToolName:  bs.name,
			}
		} else {
			blocks[payload.Index] = bs
			if payload.ContentBlock.Text != "" {
				out <- llm.Event{Kind: llm.EventTextDelta, Text: payload.ContentBlock.Text}
			}
		}
	case "content_block_delta":
		var payload struct {
			Index int `json:"index"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			return
		}
		bs := blocks[payload.Index]
		switch payload.Delta.Type {
		case "text_delta":
			out <- llm.Event{Kind: llm.EventTextDelta, Text: payload.Delta.Text}
		case "input_json_delta":
			if bs == nil {
				return
			}
			out <- llm.Event{
				Kind:       llm.EventToolCallDelta,
				ToolUseID:  bs.id,
				ToolName:   bs.name,
				InputDelta: payload.Delta.PartialJSON,
			}
		}
	case "content_block_stop":
		var payload struct {
			Index int `json:"index"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			return
		}
		bs := blocks[payload.Index]
		if bs != nil && bs.isTool {
			out <- llm.Event{
				Kind:      llm.EventToolCallEnd,
				ToolUseID: bs.id,
				ToolName:  bs.name,
			}
		}
		delete(blocks, payload.Index)
	case "message_delta":
		var payload struct {
			Delta struct {
				StopReason   string `json:"stop_reason"`
				StopSequence string `json:"stop_sequence"`
			} `json:"delta"`
			Usage struct {
				InputTokens              int `json:"input_tokens"`
				OutputTokens             int `json:"output_tokens"`
				CacheReadInputTokens     int `json:"cache_read_input_tokens"`
				CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			return
		}
		if payload.Usage.InputTokens != 0 || payload.Usage.OutputTokens != 0 ||
			payload.Usage.CacheReadInputTokens != 0 || payload.Usage.CacheCreationInputTokens != 0 {
			out <- llm.Event{
				Kind: llm.EventUsageDelta,
				Usage: llm.Usage{
					InputTokens:         payload.Usage.InputTokens,
					OutputTokens:        payload.Usage.OutputTokens,
					CacheReadTokens:     payload.Usage.CacheReadInputTokens,
					CacheCreationTokens: payload.Usage.CacheCreationInputTokens,
				},
			}
		}
		if payload.Delta.StopReason != "" {
			out <- llm.Event{
				Kind:       llm.EventStopReason,
				StopReason: normalizeStop(payload.Delta.StopReason),
			}
		}
	case "message_stop":
		// Terminal; nothing to emit.
	case "error":
		out <- llm.Event{Kind: llm.EventError, Err: fmt.Errorf("anthropic: %s", data)}
	}
}

func normalizeStop(s string) string {
	switch s {
	case "end_turn":
		return llm.StopEndTurn
	case "tool_use":
		return llm.StopToolUse
	case "max_tokens":
		return llm.StopMaxTokens
	case "stop_sequence":
		return llm.StopStop
	default:
		return s
	}
}
