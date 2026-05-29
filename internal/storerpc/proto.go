// Package storerpc is a minimal JSON-NDJSON-over-net.Conn RPC that the
// in-container agent sidecar uses to call the host's store. The host
// worker hosts a per-run Server on a Unix socket bind-mounted into the
// container, and the sidecar's Client speaks to it.
//
// Every call is one request line in, one result line out. The host
// allowlists methods (Findings.Create, Memories.Read, etc.) and rejects
// calls that don't match the authenticated (run_id, org_id, repo_id)
// tuple — defense in depth on top of the per-run socket.
package storerpc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Envelope is one request line on the wire.
type Envelope struct {
	// Token is the shared per-run secret. Required on every call.
	Token string `json:"token"`
	// Method is "<Store>.<Method>", e.g. "Findings.Create".
	Method string `json:"method"`
	// Request is the JSON-encoded method-specific request payload.
	Request json.RawMessage `json:"request,omitempty"`
}

// Reply is one response line on the wire.
type Reply struct {
	// Result is the JSON-encoded method-specific response payload.
	Result json.RawMessage `json:"result,omitempty"`
	// Error is non-empty when the call failed. Errors that map to
	// store.ErrNotFound carry ErrorCode "not_found" so the client can
	// rebuild a typed error on its side.
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// Error codes the server may set on Reply.ErrorCode.
const (
	CodeNotFound       = "not_found"
	CodeUnauthorized   = "unauthorized"
	CodeMethodNotFound = "method_not_found"
	CodeBadRequest     = "bad_request"
	CodeInternal       = "internal"
)

// writeEnvelope marshals one Envelope as a single newline-terminated
// JSON line to w.
func writeEnvelope(w io.Writer, env Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("storerpc: encode envelope: %w", err)
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("storerpc: write envelope: %w", err)
	}
	return nil
}

// readEnvelope reads one line and decodes it as an Envelope.
func readEnvelope(r *bufio.Reader) (Envelope, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return Envelope{}, io.EOF
		}
		return Envelope{}, fmt.Errorf("storerpc: read envelope: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("storerpc: decode envelope: %w", err)
	}
	return env, nil
}

// writeReply marshals one Reply as a single newline-terminated line.
func writeReply(w io.Writer, rep Reply) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("storerpc: encode reply: %w", err)
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("storerpc: write reply: %w", err)
	}
	return nil
}

// readReply reads one line and decodes it as a Reply.
func readReply(r *bufio.Reader) (Reply, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return Reply{}, io.EOF
		}
		return Reply{}, fmt.Errorf("storerpc: read reply: %w", err)
	}
	var rep Reply
	if err := json.Unmarshal(line, &rep); err != nil {
		return Reply{}, fmt.Errorf("storerpc: decode reply: %w", err)
	}
	return rep, nil
}
