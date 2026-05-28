-- 0001_init.up.sql (sqlite)
-- All IDs are UUIDv7 strings generated in Go; bound as TEXT here.

PRAGMA foreign_keys = ON;

CREATE TABLE organizations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    github_login TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_id     INTEGER UNIQUE,
    github_login  TEXT NOT NULL,
    email         TEXT,
    name          TEXT,
    avatar_url    TEXT,
    role          TEXT NOT NULL DEFAULT 'member',
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,
    CHECK (role IN ('admin','member'))
);
CREATE UNIQUE INDEX idx_users_org_login ON users(org_id, github_login);

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE oauth_tokens (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    access_token_enc    BLOB NOT NULL,
    access_token_iv     BLOB NOT NULL,
    refresh_token_enc   BLOB,
    refresh_token_iv    BLOB,
    key_version         INTEGER NOT NULL DEFAULT 1,
    scopes              TEXT,
    expires_at          DATETIME,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_oauth_user_provider ON oauth_tokens(user_id, provider);

CREATE TABLE installations (
    id                    TEXT PRIMARY KEY,
    org_id                TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_installation_id INTEGER NOT NULL UNIQUE,
    account_login         TEXT NOT NULL,
    account_type          TEXT NOT NULL,
    target_type           TEXT NOT NULL,
    permissions_json      TEXT,
    events_json           TEXT,
    suspended_at          DATETIME,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE repositories (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    installation_id TEXT REFERENCES installations(id) ON DELETE SET NULL,
    github_repo_id  INTEGER NOT NULL UNIQUE,
    full_name       TEXT NOT NULL,
    default_branch  TEXT,
    private         INTEGER NOT NULL DEFAULT 1,
    state           TEXT NOT NULL DEFAULT 'pending',
    classification_json TEXT,
    last_indexed_at DATETIME,
    last_indexed_sha TEXT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (state IN ('pending','installing','ready','failed','disabled'))
);
CREATE UNIQUE INDEX idx_repos_org_fullname ON repositories(org_id, full_name);

CREATE TABLE providers (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    base_url     TEXT NOT NULL,
    preset       TEXT,
    api_key_enc  BLOB NOT NULL,
    api_key_iv   BLOB NOT NULL,
    key_version  INTEGER NOT NULL DEFAULT 1,
    is_default   INTEGER NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (protocol IN ('anthropic','openai-compatible'))
);
CREATE UNIQUE INDEX idx_providers_org_name ON providers(org_id, name);

CREATE TABLE provider_models (
    id            TEXT PRIMARY KEY,
    provider_id   TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model         TEXT NOT NULL,
    display_name  TEXT,
    context_window INTEGER,
    input_price_per_mtok  REAL,
    output_price_per_mtok REAL,
    metadata_json TEXT,
    discovered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_provider_models_pm ON provider_models(provider_id, model);

CREATE TABLE agent_configs (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    phase        TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT 'builtin',
    active_revision_id TEXT,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_agent_configs_org_name ON agent_configs(org_id, name);

CREATE TABLE agent_config_revisions (
    id             TEXT PRIMARY KEY,
    agent_config_id TEXT NOT NULL REFERENCES agent_configs(id) ON DELETE CASCADE,
    revision       INTEGER NOT NULL,
    yaml           TEXT NOT NULL,
    model_config_json TEXT,
    import_sha     TEXT,
    created_by     TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_agent_rev_unique ON agent_config_revisions(agent_config_id, revision);

CREATE TABLE workflows (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id     TEXT REFERENCES repositories(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    active_version_id TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workflow_versions (
    id          TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    yaml        TEXT NOT NULL,
    created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_workflow_versions_unique ON workflow_versions(workflow_id, version);

CREATE TABLE runs (
    id                  TEXT PRIMARY KEY,
    repo_id             TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    workflow_version_id TEXT REFERENCES workflow_versions(id) ON DELETE SET NULL,
    trigger             TEXT NOT NULL,
    pr_number           INTEGER,
    base_sha            TEXT,
    head_sha            TEXT,
    status              TEXT NOT NULL DEFAULT 'queued',
    error_category      TEXT,
    error_message       TEXT,
    triggered_by        TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at          DATETIME,
    completed_at        DATETIME,
    CHECK (status IN ('queued','cloning','indexing','running','reporting','completed','failed','cancelled'))
);
CREATE INDEX idx_runs_repo_created ON runs(repo_id, created_at DESC);
CREATE INDEX idx_runs_status ON runs(status);

CREATE TABLE run_phases (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    seq         INTEGER NOT NULL,
    mode        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    started_at  DATETIME,
    completed_at DATETIME
);
CREATE INDEX idx_run_phases_run_seq ON run_phases(run_id, seq);

CREATE TABLE run_agent_invocations (
    id             TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    run_phase_id   TEXT REFERENCES run_phases(id) ON DELETE CASCADE,
    agent_name     TEXT NOT NULL,
    slot_id        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    provider_id    TEXT REFERENCES providers(id) ON DELETE SET NULL,
    model          TEXT,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    cost_micros    INTEGER NOT NULL DEFAULT 0,
    started_at     DATETIME,
    completed_at   DATETIME,
    error_message  TEXT
);
CREATE INDEX idx_invocations_run ON run_agent_invocations(run_id);

CREATE TABLE transcripts (
    id            TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    invocation_id TEXT REFERENCES run_agent_invocations(id) ON DELETE CASCADE,
    agent_name    TEXT NOT NULL,
    storage_uri   TEXT NOT NULL,
    byte_size     INTEGER NOT NULL DEFAULT 0,
    sha256        TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_transcripts_run ON transcripts(run_id);

CREATE TABLE timeline_events (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type  TEXT NOT NULL,
    payload_json TEXT
);
CREATE INDEX idx_timeline_run_ts ON timeline_events(run_id, ts, id);

CREATE TABLE findings (
    id              TEXT PRIMARY KEY,
    repo_id         TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    run_id          TEXT REFERENCES runs(id) ON DELETE SET NULL,
    fingerprint     TEXT,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      TEXT,
    exploitability  TEXT,
    fix_priority    TEXT,
    status          TEXT NOT NULL DEFAULT 'open',
    cwe             TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    file            TEXT,
    line_start      INTEGER,
    line_end        INTEGER,
    function_name   TEXT,
    snippet         TEXT,
    description     TEXT,
    impact          TEXT,
    remediation     TEXT,
    evidence_json   TEXT,
    flow_trace_json TEXT,
    refs_json       TEXT,
    tags_json       TEXT,
    notes_json      TEXT,
    reopened_count  INTEGER NOT NULL DEFAULT 0,
    last_resolved_at DATETIME,
    created_by      TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    duplicate_of    TEXT REFERENCES findings(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_findings_repo_fp_creator ON findings(repo_id, fingerprint, created_by);
CREATE INDEX idx_findings_repo_status ON findings(repo_id, status);
CREATE INDEX idx_findings_repo_severity ON findings(repo_id, severity);
CREATE INDEX idx_findings_cwe ON findings(cwe);

CREATE TABLE finding_actions (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action      TEXT NOT NULL,
    actor_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    reason      TEXT,
    payload_json TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_finding_actions_finding ON finding_actions(finding_id);

CREATE TABLE memories (
    id          TEXT PRIMARY KEY,
    repo_id     TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    content     TEXT NOT NULL,
    description TEXT,
    tags_json   TEXT,
    created_by  TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_memories_repo_name ON memories(repo_id, name);
CREATE INDEX idx_memories_repo_type ON memories(repo_id, type);

CREATE VIRTUAL TABLE memories_fts USING fts5(
    name, content, description, tags,
    content='memories', content_rowid='rowid'
);

CREATE TABLE exceptions (
    id          TEXT PRIMARY KEY,
    repo_id     TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint TEXT,
    path_glob   TEXT,
    cwe         TEXT,
    agent_name  TEXT,
    reason      TEXT NOT NULL,
    expires     DATETIME NOT NULL,
    approved_by TEXT NOT NULL,
    approved_for TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (fingerprint IS NOT NULL AND path_glob IS NULL AND cwe IS NULL AND agent_name IS NULL)
        OR
        (fingerprint IS NULL AND (path_glob IS NOT NULL OR cwe IS NOT NULL OR agent_name IS NOT NULL))
    )
);
CREATE INDEX idx_exceptions_repo ON exceptions(repo_id);

CREATE TABLE model_usage (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id   TEXT REFERENCES providers(id) ON DELETE SET NULL,
    model         TEXT NOT NULL,
    period_day    TEXT NOT NULL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_micros   INTEGER NOT NULL DEFAULT 0,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX idx_model_usage_unique ON model_usage(org_id, provider_id, model, period_day);
CREATE INDEX idx_model_usage_org_day ON model_usage(org_id, period_day);

CREATE TABLE pr_feedback_settings (
    repo_id              TEXT PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    check_run_enabled    INTEGER NOT NULL DEFAULT 1,
    inline_comments_enabled INTEGER NOT NULL DEFAULT 1,
    summary_comment_enabled INTEGER NOT NULL DEFAULT 1,
    inline_severity_threshold TEXT NOT NULL DEFAULT 'medium',
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE enqueued_jobs (
    id              TEXT PRIMARY KEY,
    job_type        TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    run_after       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    locked_at       DATETIME,
    locked_by       TEXT,
    last_error      TEXT
);
CREATE INDEX idx_enqueued_jobs_status_runafter ON enqueued_jobs(status, run_after);

CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    org_id      TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    actor_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    entity      TEXT,
    entity_id   TEXT,
    payload_json TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_org_created ON audit_log(org_id, created_at DESC);
