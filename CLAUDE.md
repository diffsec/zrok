# quokka Development Guide

quokka is being rewritten from a CLI to a self-hosted code-review SaaS.
The legacy CLI lives on the `legacy-cli` branch (frozen at the pre-rewrite
tip). `main` is the SaaS line: a single binary at `cmd/quokka/` runs the
web server, worker, migrator, admin tooling, and in-container agent
sidecar via cobra subcommands defined under `internal/app/`. All business
logic lives in pure-Go functions under `internal/<pkg>/operations.go`,
callable from the in-process tool registry (Brief B) and HTTP handlers
(Brief C) without going through cobra.

## Project Structure

```
quokka/
├── cmd/quokka/main.go      # tiny shim → internal/app.Execute()
├── db/migrations/          # SQLite + Postgres init schemas (golang-migrate)
├── eval/                   # Evaluation framework (legacy; unchanged)
├── internal/
│   ├── app/                # cobra subcommands: server, worker, migrate, admin, agent run
│   ├── web/                # HTTP server (PR-3); templ + middleware + handlers + static
│   │   ├── server.go
│   │   ├── middleware/     # session, csrf, auth, logging, recover, request_id
│   │   ├── handlers/       # auth, repos, runs, findings, healthz
│   │   ├── templates/      # *.templ + generated *_templ.go
│   │   ├── webctx/         # request-context key types (no-cycle helper)
│   │   └── static/         # CSS + JS
│   ├── store/              # Stores aggregate + interfaces
│   │   └── sql/{sqlite,postgres}/  # concrete adapters + tests
│   ├── crypto/             # AES-GCM cipher + keyring (env-driven master key)
│   ├── project/            # Project config, tech detection, classification, onboarding
│   │   ├── configs/        # Embedded classification rules YAML
│   │   └── operations.go   # Init, OnboardAuto, OnboardAgent
│   ├── memory/             # Memory domain types + operations.go (Read/Write/List/Search/Delete)
│   ├── finding/            # Finding domain types + operations.go (Create/List/Show/UpdateNote/Triage)
│   │   └── export/         # Format exporters (md, sarif, html, csv, json) + Export op
│   ├── exception/          # Exception types + operations.go (Add/Remove/List/Match)
│   ├── agent/              # Agent registry/config + operations.go (List/Show/Prompt/Suggest)
│   │   └── configs/agents/ # Agent YAML configs with applicability rules
│   ├── navigate/           # File ops + operations.go (List/Read/Find/Search/Symbols)
│   │   └── lsp/            # LSP client
│   ├── treesitter/         # Tree-sitter parser (gotreesitter v0.13.4)
│   ├── think/              # Thinking prompt generators (prompts.go) + operations.go
│   ├── skill/              # Embedded skill installer (go:embed)
│   ├── chunk/              # Code chunking for semantic search
│   ├── embedding/          # Embedding providers (Ollama, OpenAI, Hugging Face)
│   ├── vectordb/           # HNSW + SQLite; registry.go opens per-repo
│   ├── semantic/           # Semantic search engine + operations.go (Search/Related)
│   ├── rule/               # Detection-rule registry (still in flux; ops surface TBD in PR-2)
│   ├── sast/               # opengrep wrapper (still in flux; ops surface TBD in PR-2)
│   └── runner/             # Legacy external-orchestrator dispatcher (deprecated; kept for legacy-cli back-compat only)
├── skills/                 # Claude Code skills (legacy-cli only; SaaS uses agentloop/tools in Brief B)
└── configs/                # External configuration files (planned)
```

Business-function contract: every `operations.go` function takes a
`context.Context`, the relevant `store.<Whatever>Store` interface, and a
request struct. No global state, no `os.Stdout` writes, no cobra. Brief
B's tool registry and Brief C's HTTP handlers call these functions
directly.

## Building

```bash
go build ./cmd/quokka          # produces the SaaS binary
go test ./...                  # all unit tests
go test -short ./...           # skips testcontainers-backed Postgres tests
```

## Key Components

### Storage (`internal/store/`)
- `store.go` — `Stores` aggregate; interfaces for every persistent table
  (Orgs, Users, Sessions, OAuth, Installations, Repos, Providers,
  ProviderModels, AgentConfigs, Workflows, Runs, Events, Transcripts,
  Findings, FindingActions, Memories, Exceptions, ModelUsage,
  PRFeedback, Audit).
- `sql/sqlite/` and `sql/postgres/` — concrete impls; both register
  their builder via `init()`.
- Concrete impls live for: Orgs, Users, Sessions, OAuth, Repos, Runs,
  Providers, Findings, FindingActions, Memories, Exceptions. The rest
  (Installations, ProviderModels, AgentConfigs, Workflows, Events,
  Transcripts, ModelUsage, PRFeedback, Audit) are stubs filled in by
  PR-4/PR-5 as features arrive.

### Agent System (`internal/agent/`)
- `registry.go` — Built-in agent definitions, `SuggestAgents()`
  classification-based selection.
- `config.go` — `AgentConfig`, `ApplicabilityRule`, project-type matching.
- `prompt.go` — Prompt generator that takes a `MemoryReader` interface
  (any store with `ReadByName(name string) (*memory.Memory, error)`
  satisfies it; `memory.ReaderAdapter` wraps a SQL `MemoryStore`).
- `operations.go` — `List`, `Show`, `Prompt`, `Suggest` for the tool
  registry.

### Findings (`internal/finding/`)
- `types.go` — `Finding`, `Severity`, `Confidence`, etc.
- `fingerprint.go` — Stable per-finding hash.
- `operations.go` — `Create` (with per-creator dedup), `List`, `Show`,
  `UpdateNote`, `Triage`. `findingToRow`/`rowToFinding` move between
  the domain type and the SQL row shape.
- `export/operations.go` — `Export` that reuses `finding.List` then
  renders to the selected format (md, sarif, html, csv, json).

### Memory (`internal/memory/`)
- `types.go` — `Memory`, `MemoryType`.
- `operations.go` — `Write` (upsert), `Read`, `List`, `Search`, `Delete`.
  `ReaderAdapter` exposes `agent.MemoryReader` against a SQL store.

### Exceptions (`internal/exception/`)
- `types.go` — `Exception` with `Fingerprint` XOR `(PathGlob, CWE,
  AgentName)`. The `AgentName` axis was added in PR-1B.
- `operations.go` — `Add`, `Remove`, `List`, `Match`.

### Navigation (`internal/navigate/`)
- `lister.go`, `finder.go`, `reader.go`, `symbols.go` — primitives.
- `operations.go` — `List`, `Read`, `Find`, `Search`, `Symbols` for the
  tool registry.

### Semantic Search (`internal/semantic/`)
- `search.go`, `multihop.go` — primitives.
- `operations.go` — `Search`, `Related`.
- Backed by `internal/vectordb/` (HNSW + per-repo SQLite metastore via
  `vectordb.Registry`).

### Project Config (`internal/project/`)
- `config.go`, `detector.go`, `classifier.go`, `onboard.go` — existing.
- `operations.go` — `Init`, `OnboardAuto`, `OnboardAgent` (the
  interactive `RunWizard` retired with the legacy CLI).

### Think prompts (`internal/think/`)
- `prompts.go` — `ThinkingResult`, `ThinkingVerb`.
- `operations.go` — `Prompt(verb)` renders one of the parametric
  thinking-prompt bodies (collected, adherence, done, next, hypothesis,
  validate, dataflow). Brief B exposes one tool per verb.

### Web (`internal/web/`)
- `server.go` — http.Server wrapper; composes middleware (request_id →
  recover → logging → secure_headers → session → csrf → require_auth),
  registers routes, embeds `static/`.
- `middleware/` — session reads `q_session` cookie, slides `expires_at`
  by 30d, sets fresh cookie; CSRF is double-submit (`q_csrf` cookie
  vs `X-CSRF-Token` header or `csrf_token` form field).
- `handlers/` — `auth.go` runs the GitHub OAuth handshake (env-driven
  `QUOKKA_GITHUB_APP_CLIENT_ID`, `_CLIENT_SECRET`, `QUOKKA_GITHUB_ORG`,
  `QUOKKA_ADMIN_LOGINS`). `github_client.go` defines the narrow
  `GitHubClient` interface; tests use a fake, prod uses the http impl.
  PR-4 will fold this into `internal/github/` for App auth.
- `templates/` — a-h/templ source files (`.templ`) and generated
  siblings (`*_templ.go`). Both are committed. Regenerate with
  `templ generate -path internal/web/templates`. `mise.toml` pins the
  CLI version; `templates.go` carries the `//go:generate` directive.
- Run locally: `QUOKKA_MASTER_KEY=$(openssl rand -base64 32) \
  quokka server --addr :8080 --base-url http://localhost:8080 \
  --dsn 'sqlite:///tmp/q.db' --data-root /tmp/qd`.

## Adding New Features

### New Agent
1. Add YAML in `internal/agent/configs/agents/` (loaded via go:embed) or
   in the connected repo's `.quokka/agents/` (loaded at run start).
2. Tests under `internal/agent/`.

### New Export Format
1. Create exporter in `internal/finding/export/`.
2. Implement the `Exporter` interface.
3. Register in `export.go`.

### New SaaS Subcommand
1. Add a `newXxxCmd()` constructor in `internal/app/`.
2. Register in `internal/app/root.go`'s `init()`.

## Testing

```bash
go test ./...                   # all tests (Postgres uses testcontainers)
go test -short ./...            # skip Postgres testcontainers
go test ./internal/store/...    # storage layer only
```

Operations tests live next to each `operations.go` and spin up an
in-process SQLite-backed `Stores` aggregate so they exercise the real
adapter, not a mock.

## Evaluation

```bash
./eval/run.sh --fixture owasp --compare      # Single run vs baseline
./eval/run.sh --fixture owasp -n 10 --baseline # Generate baseline from N runs
```

The evaluation framework still runs against the legacy CLI on
`legacy-cli`; the SaaS surface gets its own eval harness in a later PR.

## Known gaps (rewrite in progress)

- **In-container agent execution is stubbed.** PR-4 ships the full
  worker → container → log-streaming → GitHub-feedback pipeline, but
  `quokka agent run --job-file ...` (the sidecar that should host the
  `workflow.Executor` inside the container) only emits a few canned
  NDJSON `TranscriptEvent` lines and exits 0. A PR-4.5 wires the
  real executor + tool registry so a webhook produces an actual LLM
  run rather than a placeholder transcript. Until then, "completed"
  runs are decorative.
