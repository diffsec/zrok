package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/finding"
)

type FindingUpdateNote struct{}

func (FindingUpdateNote) Name() string { return "finding_update_note" }
func (FindingUpdateNote) Description() string {
	return "Append a timestamped note to a finding."
}
func (FindingUpdateNote) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"id":{"type":"string"},"text":{"type":"string"}},"required":["id","text"]}`)
}

func (FindingUpdateNote) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Findings == nil {
		return "", fmt.Errorf("finding_update_note: finding store not configured")
	}
	f, err := finding.UpdateNote(ctx, env.Stores.Findings, finding.UpdateNoteRequest{
		ID:     args.ID,
		Author: env.AgentName,
		Text:   args.Text,
	})
	if err != nil {
		return "", err
	}
	return encodeJSON(f), nil
}
