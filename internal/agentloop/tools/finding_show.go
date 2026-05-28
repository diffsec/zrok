package tools

import (
	"context"
	"fmt"

	"github.com/diffsec/quokka/internal/finding"
)

type FindingShow struct{}

func (FindingShow) Name() string { return "finding_show" }
func (FindingShow) Description() string {
	return "Show one finding's full content by id."
}
func (FindingShow) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}`)
}

func (FindingShow) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		ID string `json:"id"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Findings == nil {
		return "", fmt.Errorf("finding_show: finding store not configured")
	}
	f, err := finding.Show(ctx, env.Stores.Findings, args.ID)
	if err != nil {
		return "", err
	}
	return encodeJSON(f), nil
}
