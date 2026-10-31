use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cyberboard_config::ApiConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tracing::info;

const DEMO_ACCESS_TOKEN: &str = "cyberboard-dev-token";
const DEMO_PORTAL_ACCESS_TOKEN: &str = "cyberboard-portal-dev-token";
const DEMO_TOKEN_TYPE: &str = "Bearer";
const DEMO_TOKEN_EXPIRES_IN: u64 = 3600;

#[derive(Clone)]
struct AppState {
    config: Arc<ApiConfig>,
    demo_access_token: Arc<str>,
    demo_portal_access_token: Arc<str>,
}

impl AppState {
    fn new(config: ApiConfig) -> Self {
        Self {
            config: Arc::new(config),
            demo_access_token: Arc::from(DEMO_ACCESS_TOKEN),
            demo_portal_access_token: Arc::from(DEMO_PORTAL_ACCESS_TOKEN),
        }
    }

    #[cfg(test)]
    fn with_token(config: ApiConfig, token: &'static str) -> Self {
        Self {
            config: Arc::new(config),
            demo_access_token: Arc::from(token),
            demo_portal_access_token: Arc::from(DEMO_PORTAL_ACCESS_TOKEN),
        }
    }

    fn is_authorized_with(&self, headers: &HeaderMap, expected_token: &str) -> bool {
        let authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                let mut parts = value.splitn(2, |character: char| character.is_ascii_whitespace());
                let scheme = parts.next().unwrap_or_default();
                let token = parts.next().unwrap_or_default().trim();
                (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
            });

        authorization == Some(expected_token)
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        self.is_authorized_with(headers, self.demo_access_token.as_ref())
    }

    #[allow(dead_code)]
    fn is_portal_authorized(&self, headers: &HeaderMap) -> bool {
        self.is_authorized_with(headers, self.demo_portal_access_token.as_ref())
    }
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
    id: String,
    email: String,
    display_name: String,
    roles: Vec<String>,
    permissions: Vec<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct PortalLoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    user: SessionUserResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorResponse {
    code: &'static str,
    message: &'static str,
}

fn invalid_credentials_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiErrorResponse {
            code: "invalid_credentials",
            message: "邮箱或密码错误",
        }),
    )
        .into_response()
}

fn unauthorized_response() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(ApiErrorResponse {
            code: "invalid_token",
            message: "登录状态无效",
        }),
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Bearer"),
    );
    response
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if state.is_authorized(headers) {
        Ok(())
    } else {
        Err(unauthorized_response())
    }
}

fn demo_user(config: &ApiConfig) -> SessionUserResponse {
    SessionUserResponse {
        id: "demo-admin".to_owned(),
        email: config.demo_admin_email.clone(),
        display_name: "Demo Administrator".to_owned(),
        roles: vec!["admin".to_owned()],
        permissions: vec!["*".to_owned()],
    }
}

fn demo_portal_user(config: &ApiConfig) -> SessionUserResponse {
    SessionUserResponse {
        id: "demo-user".to_owned(),
        email: config.demo_user_email.clone(),
        display_name: "Lin".to_owned(),
        roles: vec!["user".to_owned()],
        permissions: vec!["subscription:read".to_owned()],
    }
}

async fn login(State(state): State<AppState>, Json(request): Json<LoginRequest>) -> Response {
    if request.email != state.config.demo_admin_email
        || request.password != state.config.demo_admin_password
    {
        return invalid_credentials_response();
    }

    Json(LoginResponse {
        access_token: state.demo_access_token.to_string(),
        token_type: DEMO_TOKEN_TYPE,
        expires_in: DEMO_TOKEN_EXPIRES_IN,
        user: demo_user(&state.config),
    })
    .into_response()
}

async fn portal_login(
    State(state): State<AppState>,
    Json(request): Json<PortalLoginRequest>,
) -> Response {
    if request.email != state.config.demo_user_email
        || request.password != state.config.demo_user_password
    {
        return invalid_credentials_response();
    }

    Json(LoginResponse {
        access_token: state.demo_portal_access_token.to_string(),
        token_type: DEMO_TOKEN_TYPE,
        expires_in: DEMO_TOKEN_EXPIRES_IN,
        user: demo_portal_user(&state.config),
    })
    .into_response()
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

async fn session(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    Json(demo_user(&state.config)).into_response()
}

async fn admin_dashboard(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    Json(DashboardResponse {
        users: 0,
        active_subscriptions: 0,
        online_nodes: 0,
        traffic_bytes_24h: 0,
        failed_tasks: 0,
        generated_at: DEMO_GENERATED_AT,
    })
    .into_response()
}

async fn admin_nodes(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    Json(Vec::<NodeSummaryResponse>::new()).into_response()
}

async fn admin_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    Json(Vec::<UserSummaryResponse>::new()).into_response()
}

async fn admin_subscriptions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    Json(Vec::<SubscriptionSummaryResponse>::new()).into_response()
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
            "/api/v1/auth/login": {
                "post": {
                    "operationId": "login",
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/LoginRequest" } } } },
                    "responses": {
                        "200": { "description": "Development session token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/LoginResponse" } } } },
                        "401": { "description": "Invalid credentials", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } }
                    }
                }
            },
            "/api/v1/auth/portal-login": {
                "post": {
                    "operationId": "portalLogin",
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/PortalLoginRequest" } } } },
                    "responses": {
                        "200": { "description": "Development portal session token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/PortalLoginResponse" } } } },
                        "401": { "description": "Invalid credentials", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } }
                    }
                }
            },
            "/api/v1/session": {
                "get": { "operationId": "getSession", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Demo session user", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SessionUser" } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } }
            },
            "/api/v1/admin/dashboard": {
                "get": { "operationId": "getAdminDashboard", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Demo dashboard summary", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DashboardSummary" } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } }
            },
            "/api/v1/admin/nodes": {
                "get": { "operationId": "listAdminNodes", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Empty demo node list", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/NodeSummary" } } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } }
            },
            "/api/v1/admin/users": {
                "get": { "operationId": "listAdminUsers", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Empty demo user list", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/UserSummary" } } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } }
            },
            "/api/v1/admin/subscriptions": {
                "get": { "operationId": "listAdminSubscriptions", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Empty demo subscription list", "content": { "application/json": { "schema": { "type": "array", "items": { "$ref": "#/components/schemas/SubscriptionSummary" } } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } }
            }
        },
        "securitySchemes": {
            "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "opaque" }
        },
        "components": {
            "schemas": {
                "LoginRequest": {
                    "type": "object",
                    "required": ["email", "password"],
                    "properties": {
                        "email": { "type": "string", "format": "email" }, "password": { "type": "string", "format": "password" }
                    }
                },
                "PortalLoginRequest": {
                    "type": "object",
                    "required": ["email", "password"],
                    "properties": {
                        "email": { "type": "string", "format": "email" }, "password": { "type": "string", "format": "password" }
                    }
                },
                "LoginResponse": {
                    "type": "object",
                    "required": ["accessToken", "tokenType", "expiresIn", "user"],
                    "properties": {
                        "accessToken": { "type": "string" }, "tokenType": { "type": "string", "enum": ["Bearer"] },
                        "expiresIn": { "type": "integer", "format": "int64", "description": "Development hint only; the static placeholder token is not expired server-side." }, "user": { "$ref": "#/components/schemas/SessionUser" }
                    }
                },
                "PortalLoginResponse": {
                    "type": "object",
                    "required": ["accessToken", "tokenType", "expiresIn", "user"],
                    "properties": {
                        "accessToken": { "type": "string", "description": "Fixed development-only portal token." }, "tokenType": { "type": "string", "enum": ["Bearer"] },
                        "expiresIn": { "type": "integer", "format": "int64", "description": "Development hint only; the static placeholder token is not expired server-side." }, "user": { "$ref": "#/components/schemas/PortalUser" }
                    }
                },
                "PortalUser": {
                    "type": "object",
                    "required": ["id", "email", "displayName", "roles", "permissions"],
                    "properties": {
                        "id": { "type": "string", "example": "demo-user" }, "email": { "type": "string" }, "displayName": { "type": "string", "example": "Lin" },
                        "roles": { "type": "array", "items": { "type": "string", "enum": ["user"] } }, "permissions": { "type": "array", "items": { "type": "string", "enum": ["subscription:read"] } }
                    }
                },
                "ApiError": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": { "code": { "type": "string" }, "message": { "type": "string" }, "requestId": { "type": "string" } }
                },
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
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/portal-login", post(portal_login))
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
    let state = AppState::new(config);
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
    use super::{DEMO_ACCESS_TOKEN, DEMO_GENERATED_AT, DEMO_PORTAL_ACCESS_TOKEN, router};
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode, header},
    };
    use cyberboard_config::ApiConfig;
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_endpoint_is_available() {
        let state = test_state();
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

    fn test_state() -> super::AppState {
        super::AppState::with_token(
            ApiConfig {
                bind_addr: "127.0.0.1".to_owned(),
                port: 8080,
                database_url: None,
                redis_url: None,
                demo_admin_email: "admin@example.com".to_owned(),
                demo_admin_password: "password".to_owned(),
                demo_user_email: "lin@example.com".to_owned(),
                demo_user_password: "password".to_owned(),
            },
            DEMO_ACCESS_TOKEN,
        )
    }

    async fn request_json(request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let response = router(test_state()).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        (status, headers, body)
    }

    async fn get_json(path: &str, authorization: Option<&str>) -> (StatusCode, HeaderMap, Value) {
        let mut builder = Request::builder().uri(path);
        if let Some(authorization) = authorization {
            builder = builder.header(header::AUTHORIZATION, authorization);
        }
        request_json(builder.body(Body::empty()).unwrap()).await
    }

    #[tokio::test]
    async fn login_returns_token_for_demo_credentials() {
        let response = router(test_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"email":"admin@example.com","password":"password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["accessToken"], DEMO_ACCESS_TOKEN);
        assert_eq!(body["tokenType"], "Bearer");
        assert_eq!(body["expiresIn"], 3600);
        assert_eq!(body["user"]["email"], "admin@example.com");
    }

    #[tokio::test]
    async fn login_rejects_invalid_demo_credentials() {
        let (status, _, body) = request_json(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"admin@example.com","password":"wrong"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "invalid_credentials");
        assert_eq!(body["message"], "邮箱或密码错误");
    }

    #[tokio::test]
    async fn portal_login_returns_a_distinct_user_token() {
        let response = router(test_state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/portal-login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"email":"lin@example.com","password":"password"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["accessToken"], DEMO_PORTAL_ACCESS_TOKEN);
        assert_ne!(body["accessToken"], DEMO_ACCESS_TOKEN);
        assert_eq!(body["tokenType"], "Bearer");
        assert_eq!(body["expiresIn"], 3600);
        assert_eq!(body["user"]["id"], "demo-user");
        assert_eq!(body["user"]["email"], "lin@example.com");
        assert_eq!(body["user"]["displayName"], "Lin");
        assert_eq!(body["user"]["roles"], serde_json::json!(["user"]));
        assert_eq!(
            body["user"]["permissions"],
            serde_json::json!(["subscription:read"])
        );
    }

    #[tokio::test]
    async fn portal_login_rejects_admin_credentials() {
        let (status, _, body) = request_json(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/portal-login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"admin@example.com","password":"password"}"#,
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "invalid_credentials");
    }

    #[test]
    fn admin_and_portal_tokens_are_not_interchangeable() {
        let state = test_state();
        let admin_headers = HeaderMap::from_iter([(
            header::AUTHORIZATION,
            format!("Bearer {DEMO_ACCESS_TOKEN}").parse().unwrap(),
        )]);
        let portal_headers = HeaderMap::from_iter([(
            header::AUTHORIZATION,
            format!("Bearer {DEMO_PORTAL_ACCESS_TOKEN}")
                .parse()
                .unwrap(),
        )]);
        assert!(state.is_authorized(&admin_headers));
        assert!(!state.is_authorized(&portal_headers));
        assert!(state.is_portal_authorized(&portal_headers));
        assert!(!state.is_portal_authorized(&admin_headers));
    }

    #[tokio::test]
    async fn protected_endpoints_require_and_accept_bearer_token() {
        let (status, headers, body) = get_json("/api/v1/session", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(body["code"], "invalid_token");
        assert_eq!(body["message"], "登录状态无效");

        let (status, _, body) =
            get_json("/api/v1/session", Some("bEaReR   cyberboard-dev-token  ")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], "demo-admin");
        assert_eq!(body["email"], "admin@example.com");

        let (status, _, dashboard) = get_json(
            "/api/v1/admin/dashboard",
            Some("Bearer cyberboard-dev-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(dashboard["users"], 0);
        assert_eq!(dashboard["generatedAt"], DEMO_GENERATED_AT);

        for path in [
            "/api/v1/admin/nodes",
            "/api/v1/admin/users",
            "/api/v1/admin/subscriptions",
        ] {
            let (status, _, body) = get_json(path, Some("Bearer cyberboard-dev-token")).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, Value::Array(Vec::new()));
        }
    }

    #[tokio::test]
    async fn malformed_authorization_is_rejected_with_bearer_challenge() {
        for authorization in [
            "Basic cyberboard-dev-token",
            "Bearer",
            "Bearer wrong-token",
            "Bearer    ",
        ] {
            let (status, headers, body) = get_json("/api/v1/session", Some(authorization)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorization}");
            assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
            assert_eq!(body["code"], "invalid_token");
        }
    }

    #[tokio::test]
    async fn openapi_documents_frontend_paths() {
        let (status, _, document) = get_json("/openapi.json", None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(document["paths"]["/api/v1/auth/login"].is_object());
        assert!(document["paths"]["/api/v1/auth/portal-login"].is_object());
        assert!(document["components"]["schemas"]["LoginResponse"].is_object());
        assert!(document["components"]["schemas"]["PortalLoginRequest"].is_object());
        assert!(document["components"]["schemas"]["PortalLoginResponse"].is_object());
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
