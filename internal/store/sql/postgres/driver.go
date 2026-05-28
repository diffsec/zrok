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
		OAuth:          stubOAuth{},
		Installations:  stubInstallations{},
		Repos:          stubRepos{},
		Providers:      &providerStore{db: db, cipher: c},
		ProviderModels: stubProviderModels{},
		AgentConfigs:   stubAgentConfigs{},
		Workflows:      stubWorkflows{},
		Runs:           stubRuns{},
		Events:         stubEvents{},
		Transcripts:    stubTranscripts{},
		Findings:       stubFindings{},
		FindingActions: stubFindingActions{},
		Memories:       stubMemories{},
		Exceptions:     stubExceptions{},
		ModelUsage:     stubModelUsage{},
		PRFeedback:     stubPRFeedback{},
		Audit:          stubAudit{},
	}, nil
}
