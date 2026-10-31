# Cyberboard

Cyberboard is a Rust control plane for managing users, subscriptions, nodes,
traffic usage, orders, and versioned sing-box-compatible configuration. The
API uses SQLx/PostgreSQL persistence, protected admin and portal sessions, and
an outbound Agent path based on generated tonic/prost contracts and mTLS
client configuration.

## Workspace

- `apps/api`: Axum HTTP API with health, readiness, and initial OpenAPI routes.
- `apps/worker`: background-job process boundary for durable aggregation and outbox work.
- `apps/agent`: outbound node agent with tonic transport, signed desired-state verification, and atomic core configuration apply.
- `crates/domain`: transport-independent domain errors and identifiers.
- `crates/config`: environment-backed service configuration.
- `crates/agent-protocol`: versioned `proto/agent.proto` contract.
- `crates/observability`: shared structured tracing setup.
- `crates/database`: SQLx pool, migration execution, tenant-scoped repositories.
- `crates/storage`: embedded migration resources and schema contract tests.
- `crates/config-compiler`: unified config model, sing-box rendering, and Ed25519 envelopes.
- `crates/payment-provider`: payment provider contract and deterministic manual provider for local operation.

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
only. In database mode, login creates a random server-side session with a
hashed token, tenant, role, expiry, and revocation state. Static development
tokens are available only in explicit `CYBERBOARD_DEV_MODE=1` memory mode.
Set `CYBERBOARD_DEV_MODE=1`
to enable the credential fallback when no database URL is configured; without
that explicit flag, login requires a matching active database user. Set
`CYBERBOARD_TENANT_ID` to select the tenant scope (the development default is
UUID `00000000-0000-0000-0000-000000000001`).

When `CYBERBOARD_DATABASE_URL` is set, API startup connects to PostgreSQL,
executes the embedded migrations `0001` through `0006`, and ensures the
configured tenant exists. A failed connection or migration stops startup.
Without a URL, `/readyz` reports `memory_mode`; it does not claim database
health, and resource writes return a clear `database_unavailable` response.

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

The reviewable PostgreSQL schema is available under `deploy/migrations/`.
The `cyberboard-storage` crate embeds all migration files with `include_str!`;
`cyberboard-database` executes them with SQLx and exposes tenant-scoped CRUD
repositories. `usage_events` and `audit_logs` are append-only;
`usage_buckets` is a rebuildable aggregate. The optional
`crates/database/tests/postgres_smoke.rs` test becomes active when
`CYBERBOARD_DATABASE_URL` is set.

Run the worker or agent in separate terminals:

```sh
cargo run -p cyberboard-worker
cargo run -p cyberboard-agent
```

The agent accepts `CYBERBOARD_CONTROL_PLANE_URL`, `CYBERBOARD_NODE_ID`,
`CYBERBOARD_AGENT_INTERVAL_SECS`, `CYBERBOARD_AGENT_CA_CERT`,
`CYBERBOARD_AGENT_CLIENT_CERT`, `CYBERBOARD_AGENT_CLIENT_KEY`,
`CYBERBOARD_AGENT_TLS_SERVER_NAME`, `CYBERBOARD_AGENT_TRUSTED_KEY`,
`CYBERBOARD_SING_BOX_BINARY`, and `CYBERBOARD_AGENT_CONFIG_PATH`. With TLS
credentials configured it connects outbound using the generated AgentControl
client, registers, heartbeats, verifies signed desired state, applies the core
configuration atomically, and reports the result. Without TLS credentials it
stays in explicit local mode.

## Docker Compose

The development stack starts PostgreSQL, Redis, the API, and the worker:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

The database password in the compose file is development-only and must be
replaced before any shared or production deployment.

## Compatibility boundary

The Agent protocol is outbound-only by design. The control plane signs desired
state with Ed25519; the Agent checks the trusted key, target node, generation,
expiry, and payload hash before invoking the configured core binary. The public
subscription endpoint only returns nodes explicitly linked through
`subscription_nodes` and sets `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`.
