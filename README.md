# Cyberboard

Cyberboard is a Rust control plane for managing users, subscriptions, nodes,
traffic usage, and versioned sing-box-compatible configuration. The API now
has a SQLx/PostgreSQL persistence boundary while the agent mTLS execution path
remains a later milestone.

## Workspace

- `apps/api`: Axum HTTP API with health, readiness, and initial OpenAPI routes.
- `apps/worker`: background-job lifecycle placeholder.
- `apps/agent`: node-agent lifecycle placeholder.
- `crates/domain`: transport-independent domain errors and identifiers.
- `crates/config`: environment-backed service configuration.
- `crates/agent-protocol`: versioned `proto/agent.proto` contract.
- `crates/observability`: shared structured tracing setup.
- `crates/database`: SQLx pool, migration execution, tenant-scoped repositories.
- `crates/storage`: embedded migration resources and schema contract tests.

## Local development

```sh
cargo check
cargo test
cargo run -p cyberboard-api
```

Then query:

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/openapi.json
```

The API accepts `CYBERBOARD_BIND_ADDR`, `CYBERBOARD_API_PORT`,
`CYBERBOARD_DATABASE_URL`, `CYBERBOARD_REDIS_URL`,
`CYBERBOARD_DEMO_ADMIN_EMAIL`, `CYBERBOARD_DEMO_ADMIN_PASSWORD`,
`CYBERBOARD_DEMO_USER_EMAIL`, and `CYBERBOARD_DEMO_USER_PASSWORD`. The admin
credentials default to `admin@example.com`/`password`, and the portal user
credentials default to `lin@example.com`/`password`, for local development
only. `POST /api/v1/auth/login` returns `cyberboard-dev-token`, while
`POST /api/v1/auth/portal-login` returns the separate
`cyberboard-portal-dev-token`. Both return `expiresIn: 3600` as a client hint;
the static placeholder tokens are not expired server-side. These must be
replaced with persistent users, hashed passwords, expiring sessions, and token
rotation before any shared or production deployment. Set `CYBERBOARD_DEV_MODE=1`
to enable the credential fallback when no database URL is configured; without
that explicit flag, login requires a matching active database user. Set
`CYBERBOARD_TENANT_ID` to select the tenant scope (the development default is
UUID `00000000-0000-0000-0000-000000000001`).

When `CYBERBOARD_DATABASE_URL` is set, API startup connects to PostgreSQL,
executes the embedded `0001_initial.sql` and `0002_resource_fields.sql`
migrations, and ensures the configured tenant exists. A failed connection or
migration stops startup. Without a URL, `/readyz` reports `memory_mode`; it
does not claim database health, and resource writes return a clear
`database_unavailable` response.

The read-only session and admin endpoints require
`Authorization: Bearer cyberboard-dev-token` after a successful development
login:

```sh
curl -s http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"password"}'
```

The user portal login uses its own credentials and token namespace:

```sh
curl -s http://127.0.0.1:8080/api/v1/auth/portal-login \
  -H 'Content-Type: application/json' \
  -d '{"email":"lin@example.com","password":"password"}'
```

The reviewable PostgreSQL schema is available at
`deploy/migrations/0001_initial.sql` and the additive resource fields at
`deploy/migrations/0002_resource_fields.sql`. The `cyberboard-storage` crate
embeds both SQL files with `include_str!`; `cyberboard-database` executes them
with SQLx and exposes tenant-scoped CRUD repositories. `usage_events` and
`audit_logs` are append-only; `usage_buckets` is a rebuildable aggregate.

Run the worker or agent in separate terminals:

```sh
cargo run -p cyberboard-worker
cargo run -p cyberboard-agent
```

The agent accepts `CYBERBOARD_CONTROL_PLANE_URL`, `CYBERBOARD_NODE_ID`, and
`CYBERBOARD_AGENT_INTERVAL_SECS`. It does not connect to a control plane yet.

## Docker Compose

The development stack starts PostgreSQL, Redis, the API, and the worker:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

The database password in the compose file is development-only and must be
replaced before any shared or production deployment.

## Compatibility boundary

The agent protocol is outbound-only by design. Future implementation should
use mTLS, signed desired-state envelopes, generation checks, and local
configuration validation before replacing a running core configuration.
