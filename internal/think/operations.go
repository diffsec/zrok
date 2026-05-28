package think

import (
	"fmt"
	"strings"
)

// PromptRequest names which thinking verb to render. Context is free-form
// text appended to the prompt for caller-supplied framing.
type PromptRequest struct {
	Verb    ThinkingVerb
	Context string
}

// Prompt renders a thinking prompt for the named verb. The output is the
// text fragment a tool-using agent can append to its turn.
func Prompt(req PromptRequest) (*ThinkingResult, error) {
	if req.Verb == "" {
		return nil, fmt.Errorf("verb is required")
	}
	body, ok := promptBodies[req.Verb]
	if !ok {
		return nil, fmt.Errorf("unknown thinking verb %q", req.Verb)
	}
	prompt := body
	if strings.TrimSpace(req.Context) != "" {
		prompt = body + "\n\n## Context\n" + req.Context
	}
	return &ThinkingResult{
		Verb:    req.Verb,
		Prompt:  prompt,
		Context: req.Context,
	}, nil
}

// promptBodies are the parametric thinking prompts. Brief B's tool registry
// exposes one tool per verb; the registry calls Prompt(verb) and returns
// the body to the agent.
var promptBodies = map[ThinkingVerb]string{
	VerbCollected: `## Audit collected memories

Step back from the current task and audit the project's memory store.
For each memory the active agents declare in their context_memories,
verify it is present and that its content is consistent with what the
agent would expect to read.

Output:
  - present_memories: list
  - missing_memories: list of (memory_name, expecting_agents)
  - orphan_memories: memories present but referenced by nobody
  - inconsistencies: memories whose content contradicts other memories`,

	VerbAdherence: `## Check agent adherence

Verify that an agent's findings fall within its declared CWE scope
(its owns_cwes / CWEChecklist).

Output:
  - in_scope: count
  - out_of_scope: list of findings whose CWE is outside the agent's scope
  - recommendation: keep / reassign / suppress for each out-of-scope finding`,

	VerbDone: `## Score completeness

Score how complete the named agent's work is on its declared CWEs and
context memories. A CWE is "covered" when at least one finding exists,
or a memory explicitly records "no findings for CWE-XXX".

Output:
  - covered_cwes / uncovered_cwes
  - missing_required_memories
  - completeness_pct (weighted 60% memories, 40% CWE coverage)
  - recommendation: continue / done`,

	VerbNext: `## Rank next actions

From the current project state — open high-severity findings, missing
context memories, uncovered CWEs declared by applicable agents — emit a
ranked checklist of next steps.

Output: ordered list of (action, target, rationale).`,

	VerbHypothesis: `## Generate ranked CWE hypotheses

Examine the project's tech stack and memory content. Emit a ranked list
of CWE hypotheses (the most likely vulnerability classes to investigate
next) with the evidence — tech keywords, memory excerpts — that supports
each one.

Output: list of (cwe, evidence[], suggested_sink_regex, verify_command).`,

	VerbValidate: `## Validate a finding

Read the cited file at the finding's line, load surrounding context, and
verify whether the source / sink / guard claim in the finding holds.

Output:
  - verdict: likely_true_positive | uncertain_guard_present |
             sink_present_source_missing | sink_missing | inconclusive
  - notes: what you observed and why`,

	VerbDataflow: `## Trace source-to-sink chains

Within one file, locate occurrences of the source pattern and the sink
pattern. Report each candidate chain with any guard-shaped calls between
them.

Output: list of chains (source_line, sink_line, guards_between, verdict).`,
}
