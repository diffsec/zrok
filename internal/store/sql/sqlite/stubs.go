package sqlite

import (
	"context"
	"time"

	"github.com/diffsec/quokka/internal/store"
)

// Stub stores returning ErrNotImplemented. PR-1B fleshes these out.

type stubInstallations struct{}

func (stubInstallations) Create(context.Context, *store.Installation) error { return store.ErrNotImplemented }
func (stubInstallations) Get(context.Context, string) (*store.Installation, error) {
	return nil, store.ErrNotImplemented
}
func (stubInstallations) GetByGitHubID(context.Context, int64) (*store.Installation, error) {
	return nil, store.ErrNotImplemented
}
func (stubInstallations) Update(context.Context, *store.Installation) error { return store.ErrNotImplemented }
func (stubInstallations) List(context.Context, string) ([]*store.Installation, error) {
	return nil, store.ErrNotImplemented
}

type stubProviderModels struct{}

func (stubProviderModels) Upsert(context.Context, *store.ProviderModel) error {
	return store.ErrNotImplemented
}
func (stubProviderModels) List(context.Context, string) ([]*store.ProviderModel, error) {
	return nil, store.ErrNotImplemented
}
func (stubProviderModels) DeleteForProvider(context.Context, string) error { return store.ErrNotImplemented }

type stubAgentConfigs struct{}

func (stubAgentConfigs) Create(context.Context, *store.AgentConfigRow) error { return store.ErrNotImplemented }
func (stubAgentConfigs) Get(context.Context, string) (*store.AgentConfigRow, error) {
	return nil, store.ErrNotImplemented
}
func (stubAgentConfigs) GetByName(context.Context, string, string) (*store.AgentConfigRow, error) {
	return nil, store.ErrNotImplemented
}
func (stubAgentConfigs) List(context.Context, string) ([]*store.AgentConfigRow, error) {
	return nil, store.ErrNotImplemented
}
func (stubAgentConfigs) NewRevision(context.Context, *store.AgentConfigRevision) error {
	return store.ErrNotImplemented
}
func (stubAgentConfigs) ListRevisions(context.Context, string) ([]*store.AgentConfigRevision, error) {
	return nil, store.ErrNotImplemented
}
func (stubAgentConfigs) SetActiveRevision(context.Context, string, string) error {
	return store.ErrNotImplemented
}

type stubWorkflows struct{}

func (stubWorkflows) Create(context.Context, *store.Workflow) error { return store.ErrNotImplemented }
func (stubWorkflows) Get(context.Context, string) (*store.Workflow, error) {
	return nil, store.ErrNotImplemented
}
func (stubWorkflows) List(context.Context, string) ([]*store.Workflow, error) {
	return nil, store.ErrNotImplemented
}
func (stubWorkflows) NewVersion(context.Context, *store.WorkflowVersion) error {
	return store.ErrNotImplemented
}
func (stubWorkflows) GetVersion(context.Context, string) (*store.WorkflowVersion, error) {
	return nil, store.ErrNotImplemented
}
func (stubWorkflows) SetActiveVersion(context.Context, string, string) error {
	return store.ErrNotImplemented
}

type stubEvents struct{}

func (stubEvents) Append(context.Context, string, string, string) error { return store.ErrNotImplemented }
func (stubEvents) Stream(context.Context, string, time.Time) ([]*store.TimelineEvent, error) {
	return nil, store.ErrNotImplemented
}

type stubTranscripts struct{}

func (stubTranscripts) Put(context.Context, string, string, string, string, string, int64) error {
	return store.ErrNotImplemented
}
func (stubTranscripts) List(context.Context, string) ([]*store.Transcript, error) {
	return nil, store.ErrNotImplemented
}

type stubModelUsage struct{}

func (stubModelUsage) Add(context.Context, *store.ModelUsage) error { return store.ErrNotImplemented }
func (stubModelUsage) ListByDay(context.Context, string, time.Time) ([]*store.ModelUsage, error) {
	return nil, store.ErrNotImplemented
}

type stubPRFeedback struct{}

func (stubPRFeedback) Get(context.Context, string) (*store.PRFeedbackSettings, error) {
	return nil, store.ErrNotImplemented
}
func (stubPRFeedback) Upsert(context.Context, *store.PRFeedbackSettings) error {
	return store.ErrNotImplemented
}

type stubAudit struct{}

func (stubAudit) Append(context.Context, string, string, string, string, string, string) error {
	return store.ErrNotImplemented
}
