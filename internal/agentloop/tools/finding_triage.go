package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/diffsec/quokka/internal/finding"
)

type FindingTriage struct{}

func (FindingTriage) Name() string { return "finding_triage" }
func (FindingTriage) Description() string {
	return "Apply a triage plan (batch status / severity / note updates) to findings."
}
func (FindingTriage) InputSchema() []byte {
	return []byte(`{"type":"object","properties":{"plan":{"type":"object"}},"required":["plan"]}`)
}

func (FindingTriage) Call(ctx context.Context, env *Env, input []byte) (string, error) {
	var args struct {
		Plan json.RawMessage `json:"plan"`
	}
	if err := decode(input, &args); err != nil {
		return "", err
	}
	if env == nil || env.Stores == nil || env.Stores.Findings == nil {
		return "", fmt.Errorf("finding_triage: finding store not configured")
	}
	var plan finding.TriagePlan
	if err := json.Unmarshal(args.Plan, &plan); err != nil {
		return "", err
	}
	if plan.Author == "" {
		plan.Author = env.AgentName
	}
	res, err := finding.Triage(ctx, env.Stores.Findings, plan)
	if err != nil {
		return "", err
	}
	return encodeJSON(res), nil
}
