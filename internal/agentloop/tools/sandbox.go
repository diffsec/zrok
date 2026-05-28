// Package tools houses the per-tool wrappers that adapt the pure-Go
// operations functions in internal/<pkg> into agentloop.ToolHandler
// dispatchable handlers.
package tools

import (
	"errors"
	"path/filepath"
	"strings"
)

// Sandbox is the path jail rooted at the cloned-repo directory. Tool
// arguments that name files are resolved through Resolve, which rejects
// any path that escapes the root.
type Sandbox struct {
	Root string
}

// NewSandbox constructs a Sandbox rooted at absRoot. The root is
// canonicalized (symlinks-then-clean) so subsequent comparisons are
// stable.
func NewSandbox(absRoot string) *Sandbox {
	root, err := filepath.Abs(absRoot)
	if err != nil {
		root = absRoot
	}
	return &Sandbox{Root: filepath.Clean(root)}
}

// Resolve maps a relative path under the sandbox root to its absolute
// equivalent, rejecting paths that escape the jail.
func (s *Sandbox) Resolve(rel string) (string, bool) {
	if s == nil || s.Root == "" {
		return "", false
	}
	if rel == "" {
		return s.Root, true
	}
	if filepath.IsAbs(rel) {
		// Allow when already under root; reject otherwise.
		abs := filepath.Clean(rel)
		if abs == s.Root || strings.HasPrefix(abs, s.Root+string(filepath.Separator)) {
			return abs, true
		}
		return "", false
	}
	abs := filepath.Clean(filepath.Join(s.Root, rel))
	if abs == s.Root || strings.HasPrefix(abs, s.Root+string(filepath.Separator)) {
		return abs, true
	}
	return "", false
}

// ErrEscape is returned by tools when a path argument tries to escape
// the sandbox.
var ErrEscape = errors.New("sandbox: path escapes root")
