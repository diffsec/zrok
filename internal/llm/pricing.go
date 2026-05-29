package llm

import (
	"log"
	"sync"
)

// ModelPrice is the cost for one million tokens by token class. Set fields
// to 0 when a provider doesn't bill separately for cache hits.
type ModelPrice struct {
	InputPerMTok         float64
	OutputPerMTok        float64
	CacheReadPerMTok     float64
	CacheCreationPerMTok float64
}

// Prices is the static (provider_id, model) → price table. New entries are
// added here as we onboard providers; callers should not mutate.
var Prices = map[string]map[string]ModelPrice{
	"anthropic": {
		"claude-sonnet-4-5": {
			InputPerMTok: 3.00, OutputPerMTok: 15.00,
			CacheReadPerMTok: 0.30, CacheCreationPerMTok: 3.75,
		},
		"claude-opus-4-7": {
			InputPerMTok: 15.00, OutputPerMTok: 75.00,
			CacheReadPerMTok: 1.50, CacheCreationPerMTok: 18.75,
		},
		"claude-haiku-4-5": {
			InputPerMTok: 1.00, OutputPerMTok: 5.00,
			CacheReadPerMTok: 0.10, CacheCreationPerMTok: 1.25,
		},
	},
	"openai-compat": {
		"gpt-4o-mini": {
			InputPerMTok: 0.15, OutputPerMTok: 0.60,
		},
	},
}

var (
	unknownWarnedMu sync.Mutex
	unknownWarned   = map[string]bool{}
)

// Cost computes the USD cost for the given usage against the static price
// table. Unknown (providerID, model) pairs return 0 and log a one-time
// warning per pair.
func Cost(providerID, model string, u Usage) float64 {
	models, ok := Prices[providerID]
	if !ok {
		warnUnknown(providerID, model)
		return 0
	}
	p, ok := models[model]
	if !ok {
		warnUnknown(providerID, model)
		return 0
	}
	const m = 1_000_000.0
	return float64(u.InputTokens)/m*p.InputPerMTok +
		float64(u.OutputTokens)/m*p.OutputPerMTok +
		float64(u.CacheReadTokens)/m*p.CacheReadPerMTok +
		float64(u.CacheCreationTokens)/m*p.CacheCreationPerMTok
}

func warnUnknown(providerID, model string) {
	key := providerID + "/" + model
	unknownWarnedMu.Lock()
	defer unknownWarnedMu.Unlock()
	if unknownWarned[key] {
		return
	}
	unknownWarned[key] = true
	log.Printf("llm: no pricing entry for %s; cost will be reported as 0", key)
}
