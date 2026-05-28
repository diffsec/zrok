// Package sqlite is the concrete SQLite implementation of the store interfaces.
package sqlite

import (
	"context"
	"database/sql"

	"github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
)

func init() {
	store.RegisterSQLiteBuilder(build)
}

func build(ctx context.Context, db *sql.DB, c *crypto.Cipher) (*store.Stores, error) {
	return &store.Stores{
		Orgs:           &orgStore{db: db},
		Users:          &userStore{db: db},
		Sessions:       &sessionStore{db: db},
		OAuth:          &oauthStore{db: db, cipher: c},
		Installations:  &installationStore{db: db},
		Repos:          &repoStore{db: db},
		Providers:      &providerStore{db: db, cipher: c},
		ProviderModels: &providerModelStore{db: db},
		AgentConfigs:   &agentConfigStore{db: db},
		Workflows:      &workflowStore{db: db},
		Runs:           &runStore{db: db},
		Events:         &eventStore{db: db},
		Transcripts:    &transcriptStore{db: db},
		Findings:       &findingStore{db: db},
		FindingActions: &findingActionStore{db: db},
		Memories:       &memoryStore{db: db},
		Exceptions:     &exceptionStore{db: db},
		ModelUsage:     &modelUsageStore{db: db},
		PRFeedback:     &prFeedbackStore{db: db},
		Audit:          &auditStore{db: db},
		WebhookLog:     &webhookLogStore{db: db},
		Jobs:           &jobStore{db: db},
	}, nil
}
