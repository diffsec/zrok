// Package jobs holds one handler file per job type the worker can run.
// Each handler is a pure func that takes a Deps bundle and a payload —
// the worker dispatches by JobType.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/diffsec/quokka/internal/agentruntime/container"
	"github.com/diffsec/quokka/internal/github"
	"github.com/diffsec/quokka/internal/store"
	"github.com/diffsec/quokka/internal/transcript"
)

// Deps is the bundle every job handler needs. The worker constructs one
// up-front and reuses it per dispatch.
type Deps struct {
	Stores         *store.Stores
	Runtime        container.Runtime
	GitHub         *github.AppAuth
	Cloner         github.Cloner
	Feedback       github.FeedbackClient
	Broadcaster    *transcript.Broadcaster
	DataRoot       string
	BaseURL        string // for Check Run details_url
	RunnerImage    string // image tag the container runs from
	WorkerID       string // for queue Claim attribution
	Log            *slog.Logger
}

// Handler is one job handler.
type Handler func(ctx context.Context, deps *Deps, payload []byte) error

// Registry maps job type names to handlers.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{handlers: map[string]Handler{}} }

// Register adds a handler under the given type.
func (r *Registry) Register(jobType string, h Handler) { r.handlers[jobType] = h }

// Get returns the handler for the given type, or an error if unknown.
func (r *Registry) Get(jobType string) (Handler, error) {
	h, ok := r.handlers[jobType]
	if !ok {
		return nil, errors.New("worker: unknown job type " + jobType)
	}
	return h, nil
}

// Default registers the v1 job set.
func Default() *Registry {
	r := NewRegistry()
	r.Register("RunPR", RunPR)
	r.Register("RunManual", RunPR) // same body — different webhook entry
	r.Register("InstallRepo", InstallRepo)
	r.Register("IndexRepo", IndexRepo)
	return r
}

// Decode is a small helper that unmarshals a payload into v, returning a
// descriptive error.
func Decode(payload []byte, v any) error {
	if err := json.Unmarshal(payload, v); err != nil {
		return errors.New("decode job payload: " + err.Error())
	}
	return nil
}
