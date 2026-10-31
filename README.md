# Cyberboard

Cyberboard is a control-plane skeleton for managing users, subscriptions,
nodes, traffic usage, and versioned sing-box-compatible configuration. The
current repository contains the Rust process boundaries and protocol contract;
business persistence and the mTLS transport are deliberately introduced in
later milestones.

## Workspace

- `apps/api`: Axum HTTP API with health, readiness, and initial OpenAPI routes.
- `apps/worker`: background-job lifecycle placeholder.
- `apps/agent`: node-agent lifecycle placeholder.
- `crates/domain`: transport-independent domain errors and identifiers.
- `crates/config`: environment-backed service configuration.
- `crates/agent-protocol`: versioned `proto/agent.proto` contract.
- `crates/observability`: shared structured tracing setup.

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
`CYBERBOARD_DATABASE_URL`, and `CYBERBOARD_REDIS_URL`. Database and Redis are
reported as configuration state only until the persistence slice is added.

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
