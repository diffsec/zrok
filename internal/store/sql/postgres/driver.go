// Package postgres is the concrete Postgres implementation of the store interfaces.
package postgres

import (
	"context"
	"database/sql"

	"github.com/diffsec/quokka/internal/crypto"
	"github.com/diffsec/quokka/internal/store"
)

func init() {
	store.RegisterPostgresBuilder(build)
}

func build(ctx context.Context, db *sql.DB, c *crypto.Cipher) (*store.Stores, error) {
	return &store.Stores{
		Orgs:           &orgStore{db: db},
		Users:          &userStore{db: db},
		Sessions:       &sessionStore{db: db},
		OAuth:          &oauthStore{db: db, cipher: c},
		Installations:  stubInstallations{},
		Repos:          &repoStore{db: db},
		Providers:      &providerStore{db: db, cipher: c},
		ProviderModels: stubProviderModels{},
		AgentConfigs:   stubAgentConfigs{},
		Workflows:      stubWorkflows{},
		Runs:           &runStore{db: db},
		Events:         stubEvents{},
		Transcripts:    stubTranscripts{},
		Findings:       &findingStore{db: db},
		FindingActions: &findingActionStore{db: db},
		Memories:       &memoryStore{db: db},
		Exceptions:     &exceptionStore{db: db},
		ModelUsage:     stubModelUsage{},
		PRFeedback:     stubPRFeedback{},
		Audit:          stubAudit{},
	}, nil
}
