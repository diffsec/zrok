// Package store defines the storage interfaces and Stores aggregate used by
// the SaaS control plane. Concrete adapters live under store/sql/{sqlite,postgres}.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/diffsec/quokka/internal/crypto"
	sqlcommon "github.com/diffsec/quokka/internal/store/sql"
)

// ErrNotImplemented is returned by stub implementations of stores that PR-1A
// did not flesh out. Later PRs replace these stubs with concrete code.
var ErrNotImplemented = errors.New("store: not implemented")

// ErrNotFound is returned when a lookup yields no rows.
var ErrNotFound = errors.New("store: not found")

// Config controls how Open wires up the aggregate.
type Config struct {
	// DSN is "sqlite:///path/to.db" or "postgres://user:pass@host/db".
	DSN string
	// DataRoot is the on-disk root for per-repo embedding state and transcripts.
	DataRoot string
}

// Stores is the aggregate of every persistent-store interface the SaaS uses.
type Stores struct {
	Dialect sqlcommon.Dialect
	DB      *sql.DB
	Cipher  *crypto.Cipher
	Keyring *crypto.Keyring

	Orgs            OrgStore
	Users           UserStore
	Sessions        SessionStore
	OAuth           OAuthStore
	Installations   InstallationStore
	Repos           RepositoryStore
	Providers       ProviderStore
	ProviderModels  ProviderModelStore
	AgentConfigs    AgentConfigStore
	Workflows       WorkflowStore
	Runs            RunStore
	Events          EventStore
	Transcripts     TranscriptStore
	Findings        FindingStore
	FindingActions  FindingActionStore
	Memories        MemoryStore
	Exceptions      ExceptionStore
	ModelUsage      ModelUsageStore
	PRFeedback      PRFeedbackStore
	Audit           AuditStore

	// Close releases the *sql.DB.
	closer func() error
}

// Close shuts down the underlying *sql.DB.
func (s *Stores) Close() error {
	if s == nil || s.closer == nil {
		return nil
	}
	return s.closer()
}

// builderRegistry is populated by adapter packages via Register*.
var (
	sqliteBuilder   func(ctx context.Context, db *sql.DB, c *crypto.Cipher) (*Stores, error)
	postgresBuilder func(ctx context.Context, db *sql.DB, c *crypto.Cipher) (*Stores, error)
)

// RegisterSQLiteBuilder is called by the sqlite adapter's init.
func RegisterSQLiteBuilder(f func(ctx context.Context, db *sql.DB, c *crypto.Cipher) (*Stores, error)) {
	sqliteBuilder = f
}

// RegisterPostgresBuilder is called by the postgres adapter's init.
func RegisterPostgresBuilder(f func(ctx context.Context, db *sql.DB, c *crypto.Cipher) (*Stores, error)) {
	postgresBuilder = f
}

// Open boots the keyring, opens the DB, and constructs the per-dialect
// concrete store aggregate.
func Open(ctx context.Context, cfg Config) (*Stores, error) {
	kr, err := crypto.LoadKeyring()
	if err != nil {
		return nil, fmt.Errorf("crypto keyring: %w", err)
	}
	cipher := crypto.NewCipher(kr)

	dialect, db, err := sqlcommon.Open(cfg.DSN)
	if err != nil {
		return nil, err
	}
	var stores *Stores
	switch dialect {
	case sqlcommon.DialectSQLite:
		if sqliteBuilder == nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite builder not registered (import the sqlite adapter)")
		}
		stores, err = sqliteBuilder(ctx, db, cipher)
	case sqlcommon.DialectPostgres:
		if postgresBuilder == nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres builder not registered (import the postgres adapter)")
		}
		stores, err = postgresBuilder(ctx, db, cipher)
	default:
		_ = db.Close()
		return nil, fmt.Errorf("unknown dialect %q", dialect)
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	stores.Dialect = dialect
	stores.DB = db
	stores.Cipher = cipher
	stores.Keyring = kr
	stores.closer = db.Close
	return stores, nil
}

// ----------------------------------------------------------------------------
// Domain types (lightweight, store-layer-only — domain packages own canonical types)
// ----------------------------------------------------------------------------

// Org is a row in organizations.
type Org struct {
	ID          string
	Name        string
	GitHubLogin string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// User is a row in users.
type User struct {
	ID          string
	OrgID       string
	GitHubID    int64
	GitHubLogin string
	Email       string
	Name        string
	AvatarURL   string
	Role        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastLoginAt *time.Time
}

// Session is a row in sessions.
type Session struct {
	ID         string
	UserID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	IP         string
	UserAgent  string
}

// OAuthToken is a row in oauth_tokens with plaintext access/refresh tokens.
type OAuthToken struct {
	ID           string
	UserID       string
	Provider     string
	AccessToken  string
	RefreshToken string
	Scopes       string
	ExpiresAt    *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Installation is a row in installations.
type Installation struct {
	ID                   string
	OrgID                string
	GitHubInstallationID int64
	AccountLogin         string
	AccountType          string
	TargetType           string
	PermissionsJSON      string
	EventsJSON           string
	SuspendedAt          *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Repository is a row in repositories.
type Repository struct {
	ID                 string
	OrgID              string
	InstallationID     string
	GitHubRepoID       int64
	FullName           string
	DefaultBranch      string
	Private            bool
	State              string
	ClassificationJSON string
	LastIndexedAt      *time.Time
	LastIndexedSHA     string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Provider is a row in providers (api_key returned in plaintext after decrypt).
type Provider struct {
	ID        string
	OrgID     string
	Name      string
	Protocol  string
	BaseURL   string
	Preset    string
	APIKey    string
	IsDefault bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// EncryptedField is the raw ciphertext + iv + key version for a column.
type EncryptedField struct {
	Ciphertext []byte
	IV         []byte
	KeyVersion int16
}

// ----------------------------------------------------------------------------
// Store interfaces
// ----------------------------------------------------------------------------

type OrgStore interface {
	Create(ctx context.Context, o *Org) error
	Get(ctx context.Context, id string) (*Org, error)
	GetByGitHubLogin(ctx context.Context, login string) (*Org, error)
	Update(ctx context.Context, o *Org) error
	List(ctx context.Context) ([]*Org, error)
}

type UserStore interface {
	Create(ctx context.Context, u *User) error
	Get(ctx context.Context, id string) (*User, error)
	GetByGitHubID(ctx context.Context, ghID int64) (*User, error)
	GetByGitHubLogin(ctx context.Context, orgID, login string) (*User, error)
	Update(ctx context.Context, u *User) error
	List(ctx context.Context, orgID string) ([]*User, error)
}

type SessionStore interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	// Touch updates last_seen_at and slides expires_at forward.
	Touch(ctx context.Context, id string, lastSeen, expiresAt time.Time) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

type OAuthStore interface {
	Upsert(ctx context.Context, t *OAuthToken) error
	Get(ctx context.Context, userID, provider string) (*OAuthToken, error)
	Delete(ctx context.Context, userID, provider string) error
}

type InstallationStore interface {
	Create(ctx context.Context, i *Installation) error
	Get(ctx context.Context, id string) (*Installation, error)
	GetByGitHubID(ctx context.Context, ghID int64) (*Installation, error)
	Update(ctx context.Context, i *Installation) error
	List(ctx context.Context, orgID string) ([]*Installation, error)
}

type RepositoryStore interface {
	Create(ctx context.Context, r *Repository) error
	Get(ctx context.Context, id string) (*Repository, error)
	GetByGitHubID(ctx context.Context, ghID int64) (*Repository, error)
	GetByFullName(ctx context.Context, orgID, fullName string) (*Repository, error)
	Update(ctx context.Context, r *Repository) error
	List(ctx context.Context, orgID string) ([]*Repository, error)
}

type ProviderStore interface {
	Create(ctx context.Context, p *Provider) error
	Get(ctx context.Context, id string) (*Provider, error)
	List(ctx context.Context, orgID string) ([]*Provider, error)
	Update(ctx context.Context, p *Provider) error
	Delete(ctx context.Context, id string) error

	// RotateKeys re-encrypts every providers.api_key row whose key_version
	// does not match the cipher's current version. Returns rows updated.
	RotateKeys(ctx context.Context) (int64, error)
}

type ProviderModelStore interface {
	Upsert(ctx context.Context, m *ProviderModel) error
	List(ctx context.Context, providerID string) ([]*ProviderModel, error)
	DeleteForProvider(ctx context.Context, providerID string) error
}

type ProviderModel struct {
	ID                 string
	ProviderID         string
	Model              string
	DisplayName        string
	ContextWindow      int
	InputPricePerMTok  float64
	OutputPricePerMTok float64
	MetadataJSON       string
	DiscoveredAt       time.Time
}

type AgentConfigStore interface {
	Create(ctx context.Context, ac *AgentConfigRow) error
	Get(ctx context.Context, id string) (*AgentConfigRow, error)
	GetByName(ctx context.Context, orgID, name string) (*AgentConfigRow, error)
	List(ctx context.Context, orgID string) ([]*AgentConfigRow, error)
	NewRevision(ctx context.Context, rev *AgentConfigRevision) error
	ListRevisions(ctx context.Context, agentConfigID string) ([]*AgentConfigRevision, error)
	SetActiveRevision(ctx context.Context, agentConfigID, revisionID string) error
}

type AgentConfigRow struct {
	ID               string
	OrgID            string
	Name             string
	Description      string
	Phase            string
	Source           string
	ActiveRevisionID string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type AgentConfigRevision struct {
	ID              string
	AgentConfigID   string
	Revision        int
	YAML            string
	ModelConfigJSON string
	ImportSHA       string
	CreatedBy       string
	CreatedAt       time.Time
}

type WorkflowStore interface {
	Create(ctx context.Context, w *Workflow) error
	Get(ctx context.Context, id string) (*Workflow, error)
	List(ctx context.Context, orgID string) ([]*Workflow, error)
	NewVersion(ctx context.Context, v *WorkflowVersion) error
	GetVersion(ctx context.Context, id string) (*WorkflowVersion, error)
	SetActiveVersion(ctx context.Context, workflowID, versionID string) error
}

type Workflow struct {
	ID              string
	OrgID           string
	RepoID          string
	Name            string
	ActiveVersionID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type WorkflowVersion struct {
	ID         string
	WorkflowID string
	Version    int
	YAML       string
	CreatedBy  string
	CreatedAt  time.Time
}

type RunStore interface {
	Create(ctx context.Context, r *Run) error
	Get(ctx context.Context, id string) (*Run, error)
	List(ctx context.Context, repoID string, limit, offset int) ([]*Run, error)
	UpdateStatus(ctx context.Context, id, status string) error
}

type Run struct {
	ID                string
	RepoID            string
	WorkflowVersionID string
	Trigger           string
	PRNumber          int
	BaseSHA           string
	HeadSHA           string
	Status            string
	ErrorCategory     string
	ErrorMessage      string
	TriggeredBy       string
	CreatedAt         time.Time
	StartedAt         *time.Time
	CompletedAt       *time.Time
}

type EventStore interface {
	Append(ctx context.Context, runID, eventType, payloadJSON string) error
	Stream(ctx context.Context, runID string, sinceTS time.Time) ([]*TimelineEvent, error)
}

type TimelineEvent struct {
	ID          string
	RunID       string
	TS          time.Time
	EventType   string
	PayloadJSON string
}

type TranscriptStore interface {
	Put(ctx context.Context, runID, invocationID, agentName, storageURI, sha256 string, byteSize int64) error
	List(ctx context.Context, runID string) ([]*Transcript, error)
}

type Transcript struct {
	ID           string
	RunID        string
	InvocationID string
	AgentName    string
	StorageURI   string
	ByteSize     int64
	SHA256       string
	CreatedAt    time.Time
}

type FindingStore interface {
	Create(ctx context.Context, f *FindingRow) error
	Get(ctx context.Context, id string) (*FindingRow, error)
	FindByFingerprintAndCreator(ctx context.Context, repoID, fingerprint, createdBy string) (*FindingRow, error)
	List(ctx context.Context, repoID string) ([]*FindingRow, error)
	Update(ctx context.Context, f *FindingRow) error
	UpdateStatus(ctx context.Context, id, status string) error
	Delete(ctx context.Context, id string) error
}

type FindingRow struct {
	ID             string
	RepoID         string
	RunID          string
	Fingerprint    string
	Title          string
	Severity       string
	Confidence     string
	Exploitability string
	FixPriority    string
	Status         string
	CWE            string
	CVSSScore      float64
	CVSSVector     string
	File           string
	LineStart      int
	LineEnd        int
	FunctionName   string
	Snippet        string
	Description    string
	Impact         string
	Remediation    string
	EvidenceJSON   string
	FlowTraceJSON  string
	RefsJSON       string
	TagsJSON       string
	NotesJSON      string
	ReopenedCount  int
	LastResolvedAt *time.Time
	DuplicateOf    string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type FindingActionStore interface {
	Append(ctx context.Context, findingID, action, actorID, reason, payloadJSON string) error
	List(ctx context.Context, findingID string) ([]*FindingAction, error)
}

type FindingAction struct {
	ID          string
	FindingID   string
	Action      string
	ActorID     string
	Reason      string
	PayloadJSON string
	CreatedAt   time.Time
}

type MemoryStore interface {
	Upsert(ctx context.Context, m *MemoryRow) error
	Get(ctx context.Context, repoID, name string) (*MemoryRow, error)
	List(ctx context.Context, repoID string, memType string) ([]*MemoryRow, error)
	Delete(ctx context.Context, repoID, name string) error
	Search(ctx context.Context, repoID, query string) ([]*MemoryRow, error)
}

type MemoryRow struct {
	ID          string
	RepoID      string
	Name        string
	Type        string
	Content     string
	Description string
	TagsJSON    string
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ExceptionStore interface {
	Create(ctx context.Context, e *ExceptionRow) error
	Get(ctx context.Context, id string) (*ExceptionRow, error)
	List(ctx context.Context, repoID string) ([]*ExceptionRow, error)
	Delete(ctx context.Context, id string) error
	// Match returns the first non-expired exception that suppresses the
	// given (fingerprint, file, cwe, agent) tuple, or (nil, nil) when none
	// match. SQL impls fall back to in-memory matching since the XOR
	// constraint makes a single-query match impractical.
	Match(ctx context.Context, repoID, fingerprint, file, cwe, agentName string) (*ExceptionRow, error)
}

type ExceptionRow struct {
	ID          string
	RepoID      string
	Fingerprint string
	PathGlob    string
	CWE         string
	AgentName   string
	Reason      string
	Expires     time.Time
	ApprovedBy  string
	ApprovedFor string
	CreatedAt   time.Time
}

type ModelUsageStore interface {
	Add(ctx context.Context, u *ModelUsage) error
	ListByDay(ctx context.Context, orgID string, day time.Time) ([]*ModelUsage, error)
}

type ModelUsage struct {
	ID           string
	OrgID        string
	ProviderID   string
	Model        string
	PeriodDay    time.Time
	InputTokens  int64
	OutputTokens int64
	CostMicros   int64
	UpdatedAt    time.Time
}

type PRFeedbackStore interface {
	Get(ctx context.Context, repoID string) (*PRFeedbackSettings, error)
	Upsert(ctx context.Context, s *PRFeedbackSettings) error
}

type PRFeedbackSettings struct {
	RepoID                  string
	CheckRunEnabled         bool
	InlineCommentsEnabled   bool
	SummaryCommentEnabled   bool
	InlineSeverityThreshold string
	UpdatedAt               time.Time
}

type AuditStore interface {
	Append(ctx context.Context, orgID, actorID, action, entity, entityID, payloadJSON string) error
}
