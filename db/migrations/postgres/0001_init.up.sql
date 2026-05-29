-- 0001_init.up.sql (postgres)
-- IDs are UUIDv7 generated in Go and bound as uuid.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    github_login TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_id     BIGINT UNIQUE,
    github_login  TEXT NOT NULL,
    email         TEXT,
    name          TEXT,
    avatar_url    TEXT,
    role          TEXT NOT NULL DEFAULT 'member',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    CHECK (role IN ('admin','member'))
);
CREATE UNIQUE INDEX idx_users_org_login ON users(org_id, github_login);

CREATE TABLE sessions (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE oauth_tokens (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    access_token_enc    BYTEA NOT NULL,
    access_token_iv     BYTEA NOT NULL,
    refresh_token_enc   BYTEA,
    refresh_token_iv    BYTEA,
    key_version         SMALLINT NOT NULL DEFAULT 1,
    scopes              TEXT,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_oauth_user_provider ON oauth_tokens(user_id, provider);

CREATE TABLE installations (
    id                     UUID PRIMARY KEY,
    org_id                 UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    github_installation_id BIGINT NOT NULL UNIQUE,
    account_login          TEXT NOT NULL,
    account_type           TEXT NOT NULL,
    target_type            TEXT NOT NULL,
    permissions_json       JSONB,
    events_json            JSONB,
    suspended_at           TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE repositories (
    id                  UUID PRIMARY KEY,
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    installation_id     UUID REFERENCES installations(id) ON DELETE SET NULL,
    github_repo_id      BIGINT NOT NULL UNIQUE,
    full_name           TEXT NOT NULL,
    default_branch      TEXT,
    private             BOOLEAN NOT NULL DEFAULT TRUE,
    state               TEXT NOT NULL DEFAULT 'pending',
    classification_json JSONB,
    last_indexed_at     TIMESTAMPTZ,
    last_indexed_sha    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (state IN ('pending','installing','ready','failed','disabled'))
);
CREATE UNIQUE INDEX idx_repos_org_fullname ON repositories(org_id, full_name);

CREATE TABLE providers (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    protocol     TEXT NOT NULL,
    base_url     TEXT NOT NULL,
    preset       TEXT,
    api_key_enc  BYTEA NOT NULL,
    api_key_iv   BYTEA NOT NULL,
    key_version  SMALLINT NOT NULL DEFAULT 1,
    is_default   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (protocol IN ('anthropic','openai-compatible'))
);
CREATE UNIQUE INDEX idx_providers_org_name ON providers(org_id, name);

CREATE TABLE provider_models (
    id             UUID PRIMARY KEY,
    provider_id    UUID NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model          TEXT NOT NULL,
    display_name   TEXT,
    context_window INTEGER,
    input_price_per_mtok  NUMERIC,
    output_price_per_mtok NUMERIC,
    metadata_json  JSONB,
    discovered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_provider_models_pm ON provider_models(provider_id, model);

CREATE TABLE agent_configs (
    id                 UUID PRIMARY KEY,
    org_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT,
    phase              TEXT NOT NULL,
    source             TEXT NOT NULL DEFAULT 'builtin',
    active_revision_id UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_agent_configs_org_name ON agent_configs(org_id, name);

CREATE TABLE agent_config_revisions (
    id                UUID PRIMARY KEY,
    agent_config_id   UUID NOT NULL REFERENCES agent_configs(id) ON DELETE CASCADE,
    revision          INTEGER NOT NULL,
    yaml              TEXT NOT NULL,
    model_config_json JSONB,
    import_sha        TEXT,
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_agent_rev_unique ON agent_config_revisions(agent_config_id, revision);

CREATE TABLE workflows (
    id                UUID PRIMARY KEY,
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repo_id           UUID REFERENCES repositories(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    active_version_id UUID,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE workflow_versions (
    id          UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    yaml        TEXT NOT NULL,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_workflow_versions_unique ON workflow_versions(workflow_id, version);

CREATE TABLE runs (
    id                  UUID PRIMARY KEY,
    repo_id             UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    workflow_version_id UUID REFERENCES workflow_versions(id) ON DELETE SET NULL,
    trigger             TEXT NOT NULL,
    pr_number           INTEGER,
    base_sha            TEXT,
    head_sha            TEXT,
    status              TEXT NOT NULL DEFAULT 'queued',
    error_category      TEXT,
    error_message       TEXT,
    triggered_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    CHECK (status IN ('queued','cloning','indexing','running','reporting','completed','failed','cancelled'))
);
CREATE INDEX idx_runs_repo_created ON runs(repo_id, created_at DESC);
CREATE INDEX idx_runs_status ON runs(status);

CREATE TABLE run_phases (
    id           UUID PRIMARY KEY,
    run_id       UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    seq          INTEGER NOT NULL,
    mode         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX idx_run_phases_run_seq ON run_phases(run_id, seq);

CREATE TABLE run_agent_invocations (
    id             UUID PRIMARY KEY,
    run_id         UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    run_phase_id   UUID REFERENCES run_phases(id) ON DELETE CASCADE,
    agent_name     TEXT NOT NULL,
    slot_id        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    provider_id    UUID REFERENCES providers(id) ON DELETE SET NULL,
    model          TEXT,
    input_tokens   BIGINT NOT NULL DEFAULT 0,
    output_tokens  BIGINT NOT NULL DEFAULT 0,
    cost_micros    BIGINT NOT NULL DEFAULT 0,
    started_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ,
    error_message  TEXT
);
CREATE INDEX idx_invocations_run ON run_agent_invocations(run_id);

CREATE TABLE transcripts (
    id            UUID PRIMARY KEY,
    run_id        UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    invocation_id UUID REFERENCES run_agent_invocations(id) ON DELETE CASCADE,
    agent_name    TEXT NOT NULL,
    storage_uri   TEXT NOT NULL,
    byte_size     BIGINT NOT NULL DEFAULT 0,
    sha256        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_transcripts_run ON transcripts(run_id);

CREATE TABLE timeline_events (
    id           UUID PRIMARY KEY,
    run_id       UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type   TEXT NOT NULL,
    payload_json JSONB
);
CREATE INDEX idx_timeline_run_ts ON timeline_events(run_id, ts, id);

CREATE TABLE findings (
    id               UUID PRIMARY KEY,
    repo_id          UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    run_id           UUID REFERENCES runs(id) ON DELETE SET NULL,
    fingerprint      TEXT,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    confidence       TEXT,
    exploitability   TEXT,
    fix_priority     TEXT,
    status           TEXT NOT NULL DEFAULT 'open',
    cwe              TEXT,
    cvss_score       NUMERIC,
    cvss_vector      TEXT,
    file             TEXT,
    line_start       INTEGER,
    line_end         INTEGER,
    function_name    TEXT,
    snippet          TEXT,
    description      TEXT,
    impact           TEXT,
    remediation      TEXT,
    evidence_json    JSONB,
    flow_trace_json  JSONB,
    refs_json        JSONB,
    tags_json        JSONB,
    notes_json       JSONB,
    reopened_count   INTEGER NOT NULL DEFAULT 0,
    last_resolved_at TIMESTAMPTZ,
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duplicate_of     UUID REFERENCES findings(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX idx_findings_repo_fp_creator ON findings(repo_id, fingerprint, created_by);
CREATE INDEX idx_findings_repo_status ON findings(repo_id, status);
CREATE INDEX idx_findings_repo_severity ON findings(repo_id, severity);
CREATE INDEX idx_findings_cwe ON findings(cwe);

CREATE TABLE finding_actions (
    id           UUID PRIMARY KEY,
    finding_id   UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action       TEXT NOT NULL,
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    reason       TEXT,
    payload_json JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_finding_actions_finding ON finding_actions(finding_id);

CREATE TABLE memories (
    id          UUID PRIMARY KEY,
    repo_id     UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    content     TEXT NOT NULL,
    description TEXT,
    tags_json   JSONB,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    search_tsv  tsvector
);
CREATE UNIQUE INDEX idx_memories_repo_name ON memories(repo_id, name);
CREATE INDEX idx_memories_repo_type ON memories(repo_id, type);
CREATE INDEX idx_memories_search ON memories USING GIN (search_tsv);

CREATE FUNCTION memories_search_tsv_trigger() RETURNS trigger AS $$
BEGIN
    NEW.search_tsv :=
        setweight(to_tsvector('english', coalesce(NEW.name, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(NEW.description, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(NEW.content, '')), 'C');
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER memories_search_tsv_update BEFORE INSERT OR UPDATE
ON memories FOR EACH ROW EXECUTE FUNCTION memories_search_tsv_trigger();

CREATE TABLE exceptions (
    id           UUID PRIMARY KEY,
    repo_id      UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    fingerprint  TEXT,
    path_glob    TEXT,
    cwe          TEXT,
    agent_name   TEXT,
    reason       TEXT NOT NULL,
    expires      TIMESTAMPTZ NOT NULL,
    approved_by  TEXT NOT NULL,
    approved_for TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (fingerprint IS NOT NULL AND path_glob IS NULL AND cwe IS NULL AND agent_name IS NULL)
        OR
        (fingerprint IS NULL AND (path_glob IS NOT NULL OR cwe IS NOT NULL OR agent_name IS NOT NULL))
    )
);
CREATE INDEX idx_exceptions_repo ON exceptions(repo_id);

CREATE TABLE model_usage (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id   UUID REFERENCES providers(id) ON DELETE SET NULL,
    model         TEXT NOT NULL,
    period_day    DATE NOT NULL,
    input_tokens  BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cost_micros   BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_model_usage_unique ON model_usage(org_id, provider_id, model, period_day);
CREATE INDEX idx_model_usage_org_day ON model_usage(org_id, period_day);

CREATE TABLE pr_feedback_settings (
    repo_id                   UUID PRIMARY KEY REFERENCES repositories(id) ON DELETE CASCADE,
    check_run_enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    inline_comments_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    summary_comment_enabled   BOOLEAN NOT NULL DEFAULT TRUE,
    inline_severity_threshold TEXT NOT NULL DEFAULT 'medium',
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE enqueued_jobs (
    id              UUID PRIMARY KEY,
    job_type        TEXT NOT NULL,
    payload_json    JSONB NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    run_after       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at       TIMESTAMPTZ,
    locked_by       TEXT,
    last_error      TEXT
);
CREATE INDEX idx_enqueued_jobs_status_runafter ON enqueued_jobs(status, run_after);

CREATE TABLE audit_log (
    id           UUID PRIMARY KEY,
    org_id       UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action       TEXT NOT NULL,
    entity       TEXT,
    entity_id    TEXT,
    payload_json JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_org_created ON audit_log(org_id, created_at DESC);
