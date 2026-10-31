use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use cyberboard_config::ApiConfig;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone)]
struct AppState {
    config: Arc<ApiConfig>,
}

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct ReadinessChecks {
    configuration: &'static str,
    database: &'static str,
}

#[derive(Serialize)]
struct ReadinessResponse {
    service: &'static str,
    status: &'static str,
    version: &'static str,
    checks: ReadinessChecks,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionUserResponse {
    id: &'static str,
    email: &'static str,
    display_name: &'static str,
    roles: &'static [&'static str],
    permissions: &'static [&'static str],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardResponse {
    users: u64,
    active_subscriptions: u64,
    online_nodes: u64,
    traffic_bytes_24h: u64,
    failed_tasks: u64,
    generated_at: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeSummaryResponse {
    id: &'static str,
    name: &'static str,
    region: &'static str,
    address: &'static str,
    status: &'static str,
    core: &'static str,
    core_version: &'static str,
    agent_version: &'static str,
    current_config_revision: &'static str,
    latency_ms: Option<u64>,
    last_heartbeat_at: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserSummaryResponse {
    id: &'static str,
    email: &'static str,
    display_name: &'static str,
    status: &'static str,
    plan: &'static str,
    used_bytes: u64,
    quota_bytes: u64,
    expires_at: &'static str,
    last_seen_at: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionSummaryResponse {
    id: &'static str,
    user_email: &'static str,
    plan: &'static str,
    status: &'static str,
    traffic_used_bytes: u64,
    traffic_quota_bytes: u64,
    expires_at: &'static str,
    token_hint: &'static str,
}

const DEMO_GENERATED_AT: &str = "1970-01-01T00:00:00Z";

async fn session() -> Json<SessionUserResponse> {
    Json(SessionUserResponse {
        id: "demo-admin",
        email: "admin@example.invalid",
        display_name: "Demo Administrator",
        roles: &["admin"],
        permissions: &["*"],
    })
}

async fn admin_dashboard() -> Json<DashboardResponse> {
    Json(DashboardResponse {
        users: 0,
        active_subscriptions: 0,
        online_nodes: 0,
        traffic_bytes_24h: 0,
        failed_tasks: 0,
        generated_at: DEMO_GENERATED_AT,
    })
}

async fn admin_nodes() -> Json<Vec<NodeSummaryResponse>> {
    Json(Vec::new())
}

async fn admin_users() -> Json<Vec<UserSummaryResponse>> {
    Json(Vec::new())
}

async fn admin_subscriptions() -> Json<Vec<SubscriptionSummaryResponse>> {
    Json(Vec::new())
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        service: "cyberboard-api",
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    // Database wiring is intentionally deferred to the first persistence slice.
    // Keeping this explicit avoids claiming a database health check that does not
    // exist yet while allowing local and container smoke tests to start.
    let database = if state.config.database_configured() {
        "configured"
    } else {
        "not_configured"
    };

    (
        StatusCode::OK,
        Json(ReadinessResponse {
            service: "cyberboard-api",
            status: "ready",
            version: env!("CARGO_PKG_VERSION"),
            checks: ReadinessChecks {
                configuration: "ok",
                database,
            },
        }),
    )
}

async fn openapi() -> Json<Value> {
    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Cyberboard API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Initial control-plane contract. Business resources are added incrementally."
        },
        "paths": {
            "/healthz": {
                "get": { "operationId": "health", "responses": { "200": { "description": "Process is alive" } } }
            },
            "/readyz": {
                "get": { "operationId": "readiness", "responses": { "200": { "description": "Process can accept traffic" } } }
            },
            "/openapi.json": {
                "get": { "operationId": "openapi", "responses": { "200": { "description": "OpenAPI document" } } }
            },
            "/api/v1/session": {
                "get": { "operationId": "getSession", "responses": { "200": { "description": "Demo session user", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SessionUser" } } } } } }
            },
            "/api/v1/admin/dashboard": {
                "get": { "operationId": "getAdminDashboard", "responses": { "200": { "description": "Demo dashboard summary", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DashboardSummary" } } } } } }
            },
            "/api/v1/admin/nodes": {
                "get": { "operationId": "listAdminNodes", "responses": { "200": { "description": "Empty demo node list", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/NodeSummary" } } } } } } }
            },
            "/api/v1/admin/users": {
                "get": { "operationId": "listAdminUsers", "responses": { "200": { "description": "Empty demo user list", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/UserSummary" } } } } } } }
            },
            "/api/v1/admin/subscriptions": {
                "get": { "operationId": "listAdminSubscriptions", "responses": { "200": { "description": "Empty demo subscription list", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SubscriptionSummary" } } } } } } }
            }
        },
        "components": {
            "schemas": {
                "SessionUser": {
                    "type": "object",
                    "required": ["id", "email", "displayName", "roles", "permissions"],
                    "properties": {
                        "id": { "type": "string" }, "email": { "type": "string" }, "displayName": { "type": "string" },
                        "roles": { "type": "array", "items": { "type": "string" } }, "permissions": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "DashboardSummary": {
                    "type": "object",
                    "required": ["users", "activeSubscriptions", "onlineNodes", "trafficBytes24h", "failedTasks", "generatedAt"],
                    "properties": {
                        "users": { "type": "integer", "format": "int64" }, "activeSubscriptions": { "type": "integer", "format": "int64" },
                        "onlineNodes": { "type": "integer", "format": "int64" }, "trafficBytes24h": { "type": "integer", "format": "int64" },
                        "failedTasks": { "type": "integer", "format": "int64" }, "generatedAt": { "type": "string", "format": "date-time" }
                    }
                },
                "NodeSummary": {
                    "type": "object",
                    "required": ["id", "name", "region", "address", "status", "core", "coreVersion", "agentVersion", "currentConfigRevision", "latencyMs", "lastHeartbeatAt"],
                    "properties": {
                        "id": { "type": "string" }, "name": { "type": "string" }, "region": { "type": "string" }, "address": { "type": "string" },
                        "status": { "type": "string", "enum": ["online", "offline", "maintenance", "error"] }, "core": { "type": "string" },
                        "coreVersion": { "type": "string" }, "agentVersion": { "type": "string" }, "currentConfigRevision": { "type": "string" },
                        "latencyMs": { "type": ["integer", "null"], "format": "int64" }, "lastHeartbeatAt": { "type": ["string", "null"], "format": "date-time" }
                    }
                },
                "UserSummary": {
                    "type": "object",
                    "required": ["id", "email", "displayName", "status", "plan", "usedBytes", "quotaBytes", "expiresAt", "lastSeenAt"],
                    "properties": {
                        "id": { "type": "string" }, "email": { "type": "string" }, "displayName": { "type": "string" },
                        "status": { "type": "string", "enum": ["active", "suspended", "banned"] }, "plan": { "type": "string" },
                        "usedBytes": { "type": "integer", "format": "int64" }, "quotaBytes": { "type": "integer", "format": "int64" },
                        "expiresAt": { "type": "string", "format": "date" }, "lastSeenAt": { "type": ["string", "null"], "format": "date-time" }
                    }
                },
                "SubscriptionSummary": {
                    "type": "object",
                    "required": ["id", "userEmail", "plan", "status", "trafficUsedBytes", "trafficQuotaBytes", "expiresAt", "tokenHint"],
                    "properties": {
                        "id": { "type": "string" }, "userEmail": { "type": "string" }, "plan": { "type": "string" },
                        "status": { "type": "string", "enum": ["active", "pending", "expired", "revoked"] },
                        "trafficUsedBytes": { "type": "integer", "format": "int64" }, "trafficQuotaBytes": { "type": "integer", "format": "int64" },
                        "expiresAt": { "type": "string", "format": "date" }, "tokenHint": { "type": "string" }
                    }
                }
            }
        }
    }))
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/openapi.json", get(openapi))
        .route("/api/v1/session", get(session))
        .route("/api/v1/admin/dashboard", get(admin_dashboard))
        .route("/api/v1/admin/nodes", get(admin_nodes))
        .route("/api/v1/admin/users", get(admin_users))
        .route("/api/v1/admin/subscriptions", get(admin_subscriptions))
        .with_state(state)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "failed to install shutdown signal; waiting for process termination");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cyberboard_observability::init("cyberboard_api");

    let config = ApiConfig::from_env()?;
    let address = config.socket_addr()?;
    let state = AppState {
        config: Arc::new(config),
    };
    let app = router(state);
    let listener = TcpListener::bind(address).await?;

    info!(%address, "Cyberboard API listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DEMO_GENERATED_AT, router};
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use cyberboard_config::ApiConfig;
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_endpoint_is_available() {
        let state = super::AppState {
            config: Arc::new(ApiConfig {
                bind_addr: "127.0.0.1".to_owned(),
                port: 8080,
                database_url: None,
                redis_url: None,
            }),
        };
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    async fn get_json(path: &str) -> Value {
        let state = super::AppState {
            config: Arc::new(ApiConfig {
                bind_addr: "127.0.0.1".to_owned(),
                port: 8080,
                database_url: None,
                redis_url: None,
            }),
        };
        let response = router(state)
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn frontend_read_only_endpoints_match_expected_shapes() {
        let session = get_json("/api/v1/session").await;
        assert_eq!(session["id"], "demo-admin");
        assert!(session["roles"].is_array());
        assert!(session["permissions"].is_array());

        let dashboard = get_json("/api/v1/admin/dashboard").await;
        assert_eq!(dashboard["users"], 0);
        assert_eq!(dashboard["generatedAt"], DEMO_GENERATED_AT);

        for path in [
            "/api/v1/admin/nodes",
            "/api/v1/admin/users",
            "/api/v1/admin/subscriptions",
        ] {
            assert_eq!(get_json(path).await, Value::Array(Vec::new()));
        }
    }

    #[tokio::test]
    async fn openapi_documents_frontend_paths() {
        let document = get_json("/openapi.json").await;
        for path in [
            "/api/v1/session",
            "/api/v1/admin/dashboard",
            "/api/v1/admin/nodes",
            "/api/v1/admin/users",
            "/api/v1/admin/subscriptions",
        ] {
            assert!(
                document["paths"][path].is_object(),
                "missing OpenAPI path {path}"
            );
        }
    }
}
