// Package exception manages persistent suppressions for findings. Exceptions
// come in two shapes: per-finding (keyed by fingerprint) and pattern-based
// (path glob + CWE). Both require a reason, an expires date, and an
// approver — the goal is to make suppressions auditable and time-bounded
// rather than write-and-forget like older static-analysis ignore lists.
package exception

import (
	"fmt"
	"strings"
	"time"
)

// Exception is one suppression entry. It can be keyed by Fingerprint XOR
// (PathGlob, CWE, AgentName) — at least one of the pattern fields must be
// set when fingerprint is empty.
type Exception struct {
	ID          string    `yaml:"id" json:"id"`
	Fingerprint string    `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	PathGlob    string    `yaml:"path_glob,omitempty" json:"path_glob,omitempty"`
	CWE         string    `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	AgentName   string    `yaml:"agent_name,omitempty" json:"agent_name,omitempty"`
	Reason      string    `yaml:"reason" json:"reason"`
	Expires     time.Time `yaml:"expires" json:"expires"`
	ApprovedBy  string    `yaml:"approved_by" json:"approved_by"`
	ApprovedFor string    `yaml:"approved_for,omitempty" json:"approved_for,omitempty"`
	CreatedAt   time.Time `yaml:"created_at" json:"created_at"`
}

// IsFingerprint reports whether this exception targets a specific finding
// fingerprint (as opposed to a pattern).
func (e Exception) IsFingerprint() bool {
	return strings.TrimSpace(e.Fingerprint) != ""
}

// IsPattern reports whether this exception targets a non-fingerprint
// pattern: any of (PathGlob, CWE, AgentName) being set qualifies.
func (e Exception) IsPattern() bool {
	return strings.TrimSpace(e.PathGlob) != "" ||
		strings.TrimSpace(e.CWE) != "" ||
		strings.TrimSpace(e.AgentName) != ""
}

// IsExpired reports whether the exception is past its expires date as of
// the given moment (typically time.Now). Exceptions with a zero expires
// time are treated as expired — the field is mandatory.
func (e Exception) IsExpired(now time.Time) bool {
	if e.Expires.IsZero() {
		return true
	}
	return now.After(e.Expires)
}

// Validate checks that the exception has the required fields and the
// fingerprint/pattern XOR constraint. Returns the first error encountered.
func (e Exception) Validate() error {
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("reason is required")
	}
	if e.Expires.IsZero() {
		return fmt.Errorf("expires is required (suppressions must be time-bounded)")
	}
	if strings.TrimSpace(e.ApprovedBy) == "" {
		return fmt.Errorf("approved_by is required")
	}
	hasFP := e.IsFingerprint()
	hasPat := e.IsPattern()
	if hasFP && hasPat {
		return fmt.Errorf("exception cannot set both fingerprint and pattern fields (path_glob/cwe/agent_name)")
	}
	if !hasFP && !hasPat {
		return fmt.Errorf("exception must set either fingerprint or one of path_glob/cwe/agent_name")
	}
	// Path globs without a CWE are over-broad — keep the legacy guard so
	// pattern-mode suppressions stay scoped to a vulnerability class.
	if strings.TrimSpace(e.PathGlob) != "" && strings.TrimSpace(e.CWE) == "" {
		return fmt.Errorf("cwe is required when path_glob is set (suppressions must be scoped)")
	}
	return nil
}
