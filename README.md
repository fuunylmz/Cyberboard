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
`CYBERBOARD_AGENT_GRPC_ADDR`, `CYBERBOARD_AGENT_GRPC_SERVER_CERT`,
`CYBERBOARD_AGENT_GRPC_SERVER_KEY`, and `CYBERBOARD_AGENT_GRPC_CLIENT_CA`,
`CYBERBOARD_CONFIG_SIGNING_KEY`, and `CYBERBOARD_CONFIG_SIGNING_KEY_ID`,
`CYBERBOARD_DATABASE_URL`, `CYBERBOARD_REDIS_URL`,
`CYBERBOARD_DEMO_ADMIN_EMAIL`, `CYBERBOARD_DEMO_ADMIN_PASSWORD`,
`CYBERBOARD_DEMO_USER_EMAIL`, `CYBERBOARD_DEMO_USER_PASSWORD`,
`CYBERBOARD_BOOTSTRAP_ADMIN_EMAIL`, and
`CYBERBOARD_BOOTSTRAP_ADMIN_PASSWORD`. The demo admin credentials default to
`admin@example.com`/`password`, and the demo portal credentials default to
`lin@example.com`/`password`; these credentials are for memory-mode development
only. These optional bootstrap settings create the first database-mode
administrator at API startup, immediately
after the configured tenant is ensured. Set both together; the password must
contain at least 12 characters. Bootstrap is idempotent: an existing tenant
administrator is never changed, while a configured email that already belongs
to a non-admin user stops startup rather than promoting that account. With
neither setting present, startup logs an informational warning if the tenant has
no administrator. In production, rotate the bootstrap password and remove both
settings after the initial administrator has been created. Demo credentials and
static development tokens work only in explicit `CYBERBOARD_DEV_MODE=1` memory
mode; database mode always authenticates persisted users and issues persisted
server-side sessions.

When `CYBERBOARD_DATABASE_URL` is set, API startup connects to PostgreSQL,
executes the embedded migrations `0001` through the current `0015` release, and ensures the
configured tenant exists. A failed connection or migration stops startup. Migrations are
serialized with a transaction-scoped advisory lock.
Without a URL, `/readyz` reports `memory_mode`; it does not claim database
health, and resource writes return a clear `database_unavailable` response.

In memory mode, successful development login returns the static token
`cyberboard-dev-token`; only then can that value be sent to read-only session and
admin endpoints. In database mode, send the `accessToken` returned by login
instead:

```sh
curl -s http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"password"}'
```

The portal user's demo credentials are likewise memory-mode only. In database
mode, portal login requires an active non-admin database user and returns a
persisted session token.

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
`CYBERBOARD_AGENT_IDENTITY_PATH`, `CYBERBOARD_AGENT_INSECURE`,
`CYBERBOARD_AGENT_INTERVAL_SECS`, `CYBERBOARD_AGENT_CA_CERT`,
`CYBERBOARD_AGENT_CLIENT_CERT`, `CYBERBOARD_AGENT_CLIENT_KEY`,
`CYBERBOARD_AGENT_TLS_SERVER_NAME`, `CYBERBOARD_AGENT_TRUSTED_KEY`,
`CYBERBOARD_SING_BOX_BINARY`, and `CYBERBOARD_AGENT_CONFIG_PATH`. With TLS
credentials configured it connects outbound using the generated AgentControl
client, registers, heartbeats, verifies signed desired state, applies the core
configuration atomically, and reports the result. Without TLS credentials it
stays in explicit local mode. The API exposes AgentControl gRPC on
`CYBERBOARD_AGENT_GRPC_ADDR` (default `0.0.0.0:9090`). Server TLS credentials
are mandatory when database mode is enabled outside `CYBERBOARD_DEV_MODE=1`;
setting `CYBERBOARD_AGENT_GRPC_CLIENT_CA` additionally enables mutual TLS.
Registration tokens use the `<node_uuid>:<secret>` form and are cleared after
successful registration. An administrator issues a 15-minute token with
`POST /api/v1/admin/nodes/{nodeId}/registration-token` using the admin bearer
token; the clear-text value is returned once, while PostgreSQL stores only its
SHA-256 hash and lifecycle timestamps. `DELETE` on the same endpoint revokes
the current token, and a later `POST` rotates it.

The API reads `CYBERBOARD_CONFIG_SIGNING_KEY` once at startup as standard
base64 for a 32-byte Ed25519 seed. A set but invalid key stops startup; an unset
key logs a warning and disables publish/rollback with `signing_key_unavailable`.
`CYBERBOARD_CONFIG_SIGNING_KEY_ID` defaults to `config-key-1` and
`CYBERBOARD_CONFIG_ENVELOPE_TTL_SECS` defaults to 300 seconds, clamped to
60–3600. Every `GetDesiredState` call signs the stored JSON payload afresh; the
publish-time signature stored on a revision is only an audit artifact.

Config deployments begin as `pending` and change only after the Agent reports
`applied`, `rolled_back`, or a failure (recorded as `failed`). Admin rollback is
a roll-forward: it creates a new generation carrying the payload of the newest
older revision whose latest deployment is `applied`. Draft revisions with a
generation less than or equal to the new generation can no longer be published.
Migration `0013_config_deployment_lifecycle.sql` adds applied-state tracking,
rollback provenance, and deployment report fields.

The Agent stores its registration identity and public-key reference in the
identity file (default `/var/lib/cyberboard/agent-identity.json`) using an
atomic write with a private file mode. On restart it reuses the stored
`agent_id`, node ID, public key, and certificate paths; the control plane
revalidates that tuple against the node record before accepting heartbeats.
For an explicit no-database development server, set
`CYBERBOARD_AGENT_INSECURE=1` and use an `http://` control-plane URL; this
enables h2c and is rejected by the production mTLS setup.

## Docker Compose

The development stack starts PostgreSQL, Redis, the API, and the worker:

```sh
docker compose -f deploy/docker-compose.yml up --build
```

The database password in the compose file is development-only and must be
replaced before any shared or production deployment.

Compose publishes HTTP on `localhost:8080` and AgentControl gRPC on
`localhost:9090`. Development mode permits plaintext gRPC for local testing;
an Agent can connect with `CYBERBOARD_AGENT_INSECURE=1` and
`CYBERBOARD_CONTROL_PLANE_URL=http://127.0.0.1:9090`. Set
`CYBERBOARD_CONFIG_SIGNING_KEY` before publishing revisions, for example:

```sh
export CYBERBOARD_CONFIG_SIGNING_KEY="$(openssl rand -base64 32)"
docker compose -f deploy/docker-compose.yml up --build
```

Production deployments must disable `CYBERBOARD_DEV_MODE` and provide the
Agent gRPC server certificate, key, client CA, and a real signing key through
the deployment secret manager.

## Compatibility boundary

The Agent protocol is outbound-only by design. The control plane signs desired
state with Ed25519; the Agent checks the trusted key, target node, generation,
expiry, and payload hash before invoking the configured core binary. The public
subscription endpoint only returns nodes explicitly linked through
`subscription_nodes` and sets `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`.
