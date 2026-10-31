#![recursion_limit = "512"]

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::Request,
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use cyberboard_config::ApiConfig;
use cyberboard_database::{
    ConfigRevisionRecord, ConfigTemplateInput, ConfigTemplateRecord, ConfigTemplateUpdate,
    Database, NodeInput, NodeRecord, NodeUpdate, PlanInput, PlanRecord, PlanUpdate,
    SubscriptionInput, SubscriptionRecord, SubscriptionUpdate, UserRecord,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tracing::info;
use uuid::Uuid;

const DEMO_ACCESS_TOKEN: &str = "cyberboard-dev-token";
const DEMO_PORTAL_ACCESS_TOKEN: &str = "cyberboard-portal-dev-token";
const DEMO_TOKEN_TYPE: &str = "Bearer";
const DEMO_TOKEN_EXPIRES_IN: u64 = 3600;

#[derive(Clone)]
struct AppState {
    config: Arc<ApiConfig>,
    demo_access_token: Arc<str>,
    demo_portal_access_token: Arc<str>,
    database: Option<Arc<Database>>,
    portal_sessions: Arc<RwLock<HashMap<String, PortalIdentity>>>,
}

#[derive(Clone, Debug)]
struct PortalIdentity {
    user_id: String,
    email: String,
}

#[derive(Clone, Debug)]
struct AuthIdentity {
    user_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
    role: String,
}

async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(token) = state.bearer_token(request.headers()) else {
        return unauthorized_response();
    };
    if let Some(database) = state.database.as_ref() {
        match database.find_session(state.config.tenant_id, &token).await {
            Ok(Some(session)) if session.active => {
                request.extensions_mut().insert(AuthIdentity {
                    user_id: session.user_id,
                    tenant_id: state.config.tenant_id,
                    role: session.role,
                });
                return next.run(request).await;
            }
            _ => return unauthorized_response(),
        }
    }
    if state.is_authorized(request.headers()) || state.is_portal_authorized(request.headers()) {
        next.run(request).await
    } else {
        unauthorized_response()
    }
}

async fn admin_auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    auth_middleware_role(state, request, next, "admin").await
}

async fn portal_auth_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    auth_middleware_role(state, request, next, "user").await
}

async fn auth_middleware_role(
    state: AppState,
    mut request: Request<axum::body::Body>,
    next: Next,
    required_role: &str,
) -> Response {
    let Some(token) = state.bearer_token(request.headers()) else {
        return unauthorized_response();
    };
    if let Some(database) = state.database.as_ref() {
        match database.find_session(state.config.tenant_id, &token).await {
            Ok(Some(session))
                if session.active
                    && (session.role == required_role
                        || (required_role == "user" && session.role == "admin")) =>
            {
                request.extensions_mut().insert(AuthIdentity {
                    user_id: session.user_id,
                    tenant_id: state.config.tenant_id,
                    role: session.role,
                });
                return next.run(request).await;
            }
            _ => return unauthorized_response(),
        }
    }
    if (required_role == "admin" && state.is_authorized(request.headers()))
        || (required_role == "user"
            && (state.is_portal_authorized(request.headers())
                || state.is_authorized(request.headers())))
    {
        let role = if state.is_authorized(request.headers()) {
            "admin"
        } else {
            required_role
        };
        request.extensions_mut().insert(AuthIdentity {
            user_id: uuid::Uuid::nil(),
            tenant_id: state.config.tenant_id,
            role: role.to_owned(),
        });
        next.run(request).await
    } else {
        unauthorized_response()
    }
}

impl AppState {
    fn new(config: ApiConfig) -> Self {
        Self {
            config: Arc::new(config),
            demo_access_token: Arc::from(DEMO_ACCESS_TOKEN),
            demo_portal_access_token: Arc::from(DEMO_PORTAL_ACCESS_TOKEN),
            database: None,
            portal_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn with_database(config: ApiConfig, database: Option<Arc<Database>>) -> Self {
        let mut state = Self::new(config);
        state.database = database;
        if state.database.is_some() {
            state.demo_access_token = Arc::from(format!("cb-admin-{}", uuid::Uuid::new_v4()));
            state.demo_portal_access_token =
                Arc::from(format!("cb-portal-{}", uuid::Uuid::new_v4()));
        }
        state
    }

    #[cfg(test)]
    fn with_token(config: ApiConfig, token: &'static str) -> Self {
        Self {
            config: Arc::new(config),
            demo_access_token: Arc::from(token),
            demo_portal_access_token: Arc::from(DEMO_PORTAL_ACCESS_TOKEN),
            database: None,
            portal_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn is_authorized_with(&self, headers: &HeaderMap, expected_token: &str) -> bool {
        self.bearer_token(headers)
            .is_some_and(|token| token == expected_token)
    }

    fn bearer_token(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                let mut parts = value.splitn(2, |character: char| character.is_ascii_whitespace());
                let scheme = parts.next().unwrap_or_default();
                let token = parts.next().unwrap_or_default().trim();
                (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty())
                    .then_some(token.to_owned())
            })
    }

    fn is_authorized(&self, headers: &HeaderMap) -> bool {
        self.is_authorized_with(headers, self.demo_access_token.as_ref())
    }

    #[allow(dead_code)]
    fn portal_identity(&self, headers: &HeaderMap) -> Option<PortalIdentity> {
        let token = self.bearer_token(headers)?;
        if token == self.demo_portal_access_token.as_ref() {
            return Some(PortalIdentity {
                user_id: "demo-user".to_owned(),
                email: self.config.demo_user_email.clone(),
            });
        }
        self.portal_sessions.read().ok()?.get(&token).cloned()
    }

    fn is_portal_authorized(&self, headers: &HeaderMap) -> bool {
        self.portal_identity(headers).is_some()
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

#[derive(Deserialize, Default)]
struct PaginationQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    page: Option<i64>,
    #[serde(rename = "pageSize")]
    page_size: Option<i64>,
    search: Option<String>,
    status: Option<String>,
}

impl PaginationQuery {
    fn bounded_limit(&self) -> i64 {
        self.page_size.or(self.limit).unwrap_or(50).clamp(1, 100)
    }

    fn bounded_offset(&self) -> i64 {
        if let Some(page) = self.page {
            (page.max(1) - 1) * self.bounded_limit()
        } else {
            self.offset.unwrap_or(0).max(0)
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest {
    email: String,
    password: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateUserRequest {
    email: Option<String>,
    display_name: Option<String>,
    status: Option<String>,
    password: Option<String>,
}

fn service_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiErrorResponse {
            code: "database_unavailable",
            message: "数据库未配置或不可用",
        }),
    )
        .into_response()
}

fn internal_database_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiErrorResponse {
            code: "database_error",
            message: "数据库操作失败",
        }),
    )
        .into_response()
}

fn hash_password(password: &str) -> Result<String, Response> {
    use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| internal_database_response())
}

async fn credentials_match(
    state: &AppState,
    email: &str,
    password: &str,
    fallback_email: &str,
    fallback_password: &str,
    require_admin: bool,
) -> bool {
    if let Some(database) = state.database.as_ref() {
        let credentials = match database
            .find_user_credentials(state.config.tenant_id, email)
            .await
        {
            Ok(Some(credentials)) => credentials,
            Ok(None) => {
                return state.config.dev_mode
                    && email == fallback_email
                    && password == fallback_password;
            }
            Err(_) => return false,
        };
        if credentials.status != "active" {
            return false;
        }
        if !role_allowed(&credentials.roles, require_admin) {
            return false;
        }
        return PasswordHash::new(&credentials.password_hash)
            .ok()
            .is_some_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            });
    }

    state.config.dev_mode && email == fallback_email && password == fallback_password
}

fn role_allowed(roles: &[String], require_admin: bool) -> bool {
    let is_admin = roles.iter().any(|role| role == "admin");
    if require_admin { is_admin } else { !is_admin }
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
    if state.database.is_some() {
        return Ok(());
    }
    if state.is_authorized(headers) {
        Ok(())
    } else {
        Err(unauthorized_response())
    }
}

fn require_portal_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if state.database.is_some() {
        return Ok(());
    }
    if state.is_portal_authorized(headers) {
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
    if !credentials_match(
        &state,
        &request.email,
        &request.password,
        &state.config.demo_admin_email,
        &state.config.demo_admin_password,
        true,
    )
    .await
    {
        return invalid_credentials_response();
    }
    let access_token = if state.database.is_some() {
        format!("cb-admin-{}", uuid::Uuid::new_v4())
    } else {
        state.demo_access_token.to_string()
    };
    if let Some(database) = state.database.as_ref() {
        if let Ok(Some(user)) = database
            .find_user_credentials(state.config.tenant_id, &request.email)
            .await
        {
            if database
                .create_session(
                    state.config.tenant_id,
                    user.id,
                    &access_token,
                    "admin",
                    3600,
                )
                .await
                .is_err()
            {
                return internal_database_response();
            }
        }
    }

    Json(LoginResponse {
        access_token,
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
    if !credentials_match(
        &state,
        &request.email,
        &request.password,
        &state.config.demo_user_email,
        &state.config.demo_user_password,
        false,
    )
    .await
    {
        return invalid_credentials_response();
    }

    let (access_token, portal_user) = if let Some(database) = state.database.as_ref() {
        let credentials = match database
            .find_user_credentials(state.config.tenant_id, &request.email)
            .await
        {
            Ok(Some(value)) => value,
            _ => return invalid_credentials_response(),
        };
        let token = format!("cb-portal-{}", uuid::Uuid::new_v4());
        if let Ok(mut sessions) = state.portal_sessions.write() {
            sessions.insert(
                token.clone(),
                PortalIdentity {
                    user_id: credentials.id.to_string(),
                    email: credentials.email.clone(),
                },
            );
        }
        if database
            .create_session(state.config.tenant_id, credentials.id, &token, "user", 3600)
            .await
            .is_err()
        {
            return internal_database_response();
        }
        (
            token,
            SessionUserResponse {
                id: credentials.id.to_string(),
                email: credentials.email,
                display_name: credentials.display_name,
                roles: vec!["user".to_owned()],
                permissions: vec!["subscription:read".to_owned()],
            },
        )
    } else {
        (
            state.demo_portal_access_token.to_string(),
            demo_portal_user(&state.config),
        )
    };

    Json(LoginResponse {
        access_token,
        token_type: DEMO_TOKEN_TYPE,
        expires_in: DEMO_TOKEN_EXPIRES_IN,
        user: portal_user,
    })
    .into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = state.bearer_token(&headers) else {
        return unauthorized_response();
    };
    if let Some(database) = state.database.as_ref() {
        let _ = database
            .revoke_session(state.config.tenant_id, &token)
            .await;
    }
    if let Ok(mut sessions) = state.portal_sessions.write() {
        sessions.remove(&token);
    }
    StatusCode::NO_CONTENT.into_response()
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
struct UserSummaryResponse {
    id: String,
    email: String,
    display_name: String,
    status: String,
    plan: String,
    used_bytes: u64,
    quota_bytes: u64,
    expires_at: String,
    last_seen_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserListResponse {
    items: Vec<UserSummaryResponse>,
    total: i64,
    page: i64,
    page_size: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanSummaryResponse {
    id: String,
    name: String,
    description: String,
    price_cents: i64,
    currency: String,
    duration_days: i32,
    quota_bytes: i64,
    device_limit: i32,
    status: String,
    node_group_ids: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeSummaryOwnedResponse {
    id: String,
    name: String,
    region: String,
    address: String,
    status: String,
    core: String,
    core_version: String,
    agent_version: String,
    current_config_revision: Option<String>,
    latency_ms: Option<u64>,
    last_heartbeat_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionOwnedResponse {
    id: String,
    user_email: String,
    plan: String,
    status: String,
    traffic_used_bytes: i64,
    traffic_quota_bytes: i64,
    expires_at: String,
    token_hint: String,
    subscription_url: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortalUsageResponse {
    used_bytes: i64,
    quota_bytes: i64,
    today_bytes: i64,
    projected_bytes: i64,
    period_start: String,
    period_end: String,
    daily: Vec<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceListResponse<T> {
    items: Vec<T>,
    total: i64,
    page: i64,
    page_size: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanRequest {
    name: Option<String>,
    description: Option<String>,
    price_cents: Option<i64>,
    currency: Option<String>,
    duration_days: Option<i32>,
    quota_bytes: Option<i64>,
    device_limit: Option<i32>,
    status: Option<String>,
    node_group_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeRequest {
    name: Option<String>,
    region: Option<String>,
    address: Option<String>,
    port: Option<i32>,
    core: Option<String>,
    core_version: Option<String>,
    agent_version: Option<String>,
    status: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionRequest {
    user_id: Option<uuid::Uuid>,
    plan_id: Option<uuid::Uuid>,
    starts_at: Option<String>,
    expires_at: Option<String>,
    status: Option<String>,
}

const DEMO_GENERATED_AT: &str = "1970-01-01T00:00:00Z";

async fn session(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    if identity.role == "admin" {
        return Json(demo_user(&state.config)).into_response();
    }
    Json(demo_portal_user(&state.config)).into_response()
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

async fn admin_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationQuery>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let limit = pagination.bounded_limit();
    let offset = pagination.bounded_offset();
    let items = match database
        .list_nodes(
            state.config.tenant_id,
            limit,
            offset,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(items) => items.into_iter().map(node_summary_owned).collect(),
        Err(_) => return internal_database_response(),
    };
    let total = match database
        .count_nodes(
            state.config.tenant_id,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return internal_database_response(),
    };
    Json(ResourceListResponse {
        items,
        total,
        page: offset / limit + 1,
        page_size: limit,
    })
    .into_response()
}

fn user_summary(record: UserRecord) -> UserSummaryResponse {
    UserSummaryResponse {
        id: record.id.to_string(),
        email: record.email,
        display_name: record.display_name,
        status: record.status,
        plan: String::new(),
        used_bytes: 0,
        quota_bytes: 0,
        expires_at: String::new(),
        last_seen_at: None,
    }
}

async fn admin_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationQuery>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };

    let limit = pagination.bounded_limit();
    let offset = pagination.bounded_offset();
    let items = match database
        .list_users(
            state.config.tenant_id,
            limit,
            offset,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(items) => items.into_iter().map(user_summary).collect(),
        Err(_) => return internal_database_response(),
    };
    let total = match database
        .count_users(
            state.config.tenant_id,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(total) => total,
        Err(_) => return internal_database_response(),
    };

    Json(UserListResponse {
        items,
        total,
        page: offset / limit + 1,
        page_size: limit,
    })
    .into_response()
}

async fn create_admin_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    if request.email.trim().is_empty()
        || request.password.is_empty()
        || request.display_name.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorResponse {
                code: "invalid_input",
                message: "邮箱、密码和显示名称不能为空",
            }),
        )
            .into_response();
    }
    let password_hash = match hash_password(&request.password) {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    match database
        .create_user(
            state.config.tenant_id,
            request.email.trim(),
            &password_hash,
            request.display_name.trim(),
        )
        .await
    {
        Ok(record) => (StatusCode::CREATED, Json(user_summary(record))).into_response(),
        Err(error) if error.is_conflict() => conflict_response("邮箱已存在"),
        Err(_) => internal_database_response(),
    }
}

async fn update_admin_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let password_hash = match request.password.as_deref() {
        Some(password) if password.is_empty() => return invalid_input_response("密码不能为空"),
        Some(password) => match hash_password(password) {
            Ok(hash) => Some(hash),
            Err(response) => return response,
        },
        None => None,
    };
    match database
        .update_user(
            state.config.tenant_id,
            user_id,
            request.email.as_deref(),
            request.display_name.as_deref(),
            request.status.as_deref(),
            password_hash.as_deref(),
        )
        .await
    {
        Ok(Some(record)) => Json(user_summary(record)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                code: "not_found",
                message: "用户不存在",
            }),
        )
            .into_response(),
        Err(_) => internal_database_response(),
    }
}

async fn delete_admin_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database.delete_user(state.config.tenant_id, user_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiErrorResponse {
                code: "not_found",
                message: "用户不存在",
            }),
        )
            .into_response(),
        Err(_) => internal_database_response(),
    }
}

fn strings_from_json(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn plan_summary(record: PlanRecord) -> PlanSummaryResponse {
    PlanSummaryResponse {
        id: record.id.to_string(),
        name: record.name,
        description: record.description,
        price_cents: record.price_cents,
        currency: record.currency,
        duration_days: record.duration_days,
        quota_bytes: record.quota_bytes,
        device_limit: record.device_limit,
        status: record.status,
        node_group_ids: strings_from_json(&record.node_group_ids),
    }
}

fn node_summary_owned(record: NodeRecord) -> NodeSummaryOwnedResponse {
    NodeSummaryOwnedResponse {
        id: record.id.to_string(),
        name: record.name,
        region: record.region,
        address: record.address,
        status: record.status,
        core: record.core,
        core_version: record.core_version,
        agent_version: record.agent_version,
        current_config_revision: record
            .current_config_revision
            .map(|value| value.to_string()),
        latency_ms: None,
        last_heartbeat_at: record.last_heartbeat_at,
    }
}

fn subscription_summary_owned(
    record: SubscriptionRecord,
    include_url: bool,
) -> SubscriptionOwnedResponse {
    let token_hint = record
        .subscription_token
        .as_deref()
        .map(|token| {
            if token.len() > 8 {
                format!("{}…", &token[..8])
            } else {
                token.to_owned()
            }
        })
        .unwrap_or_default();
    SubscriptionOwnedResponse {
        id: record.id.to_string(),
        user_email: record.user_email,
        plan: record.plan,
        status: record.status,
        traffic_used_bytes: record.traffic_used_bytes,
        traffic_quota_bytes: record.traffic_quota_bytes,
        expires_at: record.expires_at,
        token_hint,
        subscription_url: include_url
            .then(|| record.subscription_token.clone())
            .flatten()
            .map(|token| format!("/subscribe/{token}")),
    }
}

async fn admin_plans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationQuery>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let limit = pagination.bounded_limit();
    let offset = pagination.bounded_offset();
    let items = match database
        .list_plans(
            state.config.tenant_id,
            limit,
            offset,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(items) => items.into_iter().map(plan_summary).collect(),
        Err(_) => return internal_database_response(),
    };
    let total = match database
        .count_plans(
            state.config.tenant_id,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return internal_database_response(),
    };
    Json(ResourceListResponse {
        items,
        total,
        page: offset / limit + 1,
        page_size: limit,
    })
    .into_response()
}

async fn create_admin_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PlanRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let input = PlanInput {
        name: request.name.unwrap_or_default(),
        description: request.description.unwrap_or_default(),
        price_cents: request.price_cents.unwrap_or(0),
        currency: request.currency.unwrap_or_else(|| "USD".to_owned()),
        duration_days: request.duration_days.unwrap_or(30),
        quota_bytes: request.quota_bytes.unwrap_or(0),
        device_limit: request.device_limit.unwrap_or(1),
        status: request.status.unwrap_or_else(|| "active".to_owned()),
        node_group_ids: Value::Array(
            request
                .node_group_ids
                .unwrap_or_default()
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    };
    match database.create_plan(state.config.tenant_id, &input).await {
        Ok(record) => (StatusCode::CREATED, Json(plan_summary(record))).into_response(),
        Err(_) => internal_database_response(),
    }
}

async fn update_admin_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(plan_id): Path<uuid::Uuid>,
    Json(request): Json<PlanRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let update = PlanUpdate {
        name: request.name,
        description: request.description,
        price_cents: request.price_cents,
        currency: request.currency,
        duration_days: request.duration_days,
        quota_bytes: request.quota_bytes,
        device_limit: request.device_limit,
        status: request.status,
        node_group_ids: request
            .node_group_ids
            .map(|items| Value::Array(items.into_iter().map(Value::String).collect())),
    };
    match database
        .update_plan(state.config.tenant_id, plan_id, &update)
        .await
    {
        Ok(Some(record)) => Json(plan_summary(record)).into_response(),
        Ok(None) => not_found_response("套餐不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn delete_admin_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(plan_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database.delete_plan(state.config.tenant_id, plan_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found_response("套餐不存在"),
        Err(_) => internal_database_response(),
    }
}

fn not_found_response(message: &'static str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiErrorResponse {
            code: "not_found",
            message,
        }),
    )
        .into_response()
}

async fn create_admin_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NodeRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let input = NodeInput {
        name: request.name.unwrap_or_default(),
        region: request.region.unwrap_or_default(),
        address: request.address.unwrap_or_default(),
        port: request.port.unwrap_or(443),
        core: request.core.unwrap_or_else(|| "sing-box".to_owned()),
        core_version: request.core_version.unwrap_or_default(),
        agent_version: request
            .agent_version
            .unwrap_or_else(|| "unknown".to_owned()),
        tags: Value::Array(
            request
                .tags
                .unwrap_or_default()
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    };
    match database.create_node(state.config.tenant_id, &input).await {
        Ok(record) => (StatusCode::CREATED, Json(node_summary_owned(record))).into_response(),
        Err(_) => internal_database_response(),
    }
}

async fn update_admin_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<uuid::Uuid>,
    Json(request): Json<NodeRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let update = NodeUpdate {
        name: request.name,
        region: request.region,
        address: request.address,
        port: request.port,
        core: request.core,
        core_version: request.core_version,
        status: request.status,
        tags: request
            .tags
            .map(|items| Value::Array(items.into_iter().map(Value::String).collect())),
    };
    match database
        .update_node(state.config.tenant_id, node_id, &update)
        .await
    {
        Ok(Some(record)) => Json(node_summary_owned(record)).into_response(),
        Ok(None) => not_found_response("节点不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn delete_admin_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<uuid::Uuid>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database.delete_node(state.config.tenant_id, node_id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found_response("节点不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn create_admin_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SubscriptionRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let Some(user_id) = request.user_id else {
        return invalid_input_response("用户 ID 不能为空");
    };
    let Some(plan_id) = request.plan_id else {
        return invalid_input_response("套餐 ID 不能为空");
    };
    let input = SubscriptionInput {
        user_id,
        plan_id,
        starts_at: request.starts_at,
        expires_at: request.expires_at,
        subscription_token: format!("cb_{}", uuid::Uuid::new_v4().simple()),
    };
    match database
        .create_subscription(state.config.tenant_id, &input)
        .await
    {
        Ok(record) => (
            StatusCode::CREATED,
            Json(subscription_summary_owned(record, false)),
        )
            .into_response(),
        Err(_) => internal_database_response(),
    }
}

async fn update_admin_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(request): Json<SubscriptionRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let update = SubscriptionUpdate {
        plan_id: request.plan_id,
        status: request.status,
        starts_at: request.starts_at,
    };
    match database
        .update_subscription(state.config.tenant_id, id, &update)
        .await
    {
        Ok(Some(record)) => Json(subscription_summary_owned(record, false)).into_response(),
        Ok(None) => not_found_response("订阅不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn delete_admin_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .delete_subscription(state.config.tenant_id, id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found_response("订阅不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn portal_subscription(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    if let Err(response) = require_portal_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .find_subscription_for_user(state.config.tenant_id, identity.user_id)
        .await
    {
        Ok(Some(record)) => Json(subscription_summary_owned(record, true)).into_response(),
        Ok(None) => not_found_response("当前没有生效订阅"),
        Err(_) => internal_database_response(),
    }
}

async fn portal_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    if let Err(response) = require_portal_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .find_subscription_for_user(state.config.tenant_id, identity.user_id)
        .await
    {
        Ok(Some(record)) => Json(PortalUsageResponse {
            used_bytes: record.traffic_used_bytes,
            quota_bytes: record.traffic_quota_bytes,
            today_bytes: 0,
            projected_bytes: record.traffic_used_bytes,
            period_start: String::new(),
            period_end: record.expires_at,
            daily: Vec::new(),
        })
        .into_response(),
        Ok(None) => not_found_response("当前没有可用用量"),
        Err(_) => internal_database_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateOrderRequest {
    plan_id: Uuid,
}

fn order_json(order: &cyberboard_database::OrderRecord) -> Value {
    json!({
        "id": order.id,
        "status": order.status,
        "amountCents": order.amount_cents,
        "currency": order.currency,
        "createdAt": order.created_at,
        "plan": order.plan
    })
}

async fn create_my_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthIdentity>,
    Json(request): Json<CreateOrderRequest>,
) -> Response {
    let Some(idempotency_key) = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
    else {
        return invalid_input_response("Idempotency-Key 不能为空");
    };
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .create_order(
            identity.tenant_id,
            identity.user_id,
            request.plan_id,
            idempotency_key.trim(),
        )
        .await
    {
        Ok(order) => (StatusCode::CREATED, Json(order_json(&order))).into_response(),
        Err(error) if error.is_conflict() => conflict_response("Idempotency-Key 已被其他订单使用"),
        Err(_) => internal_database_response(),
    }
}

async fn mark_admin_order_paid(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_id): Path<Uuid>,
) -> Response {
    let event_id = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("manual-payment");
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .mark_order_paid_v2(
            state.config.tenant_id,
            order_id,
            "manual",
            &format!("manual-{order_id}"),
            event_id,
        )
        .await
    {
        Ok(order) => Json(order_json(&order)).into_response(),
        Err(cyberboard_database::DatabaseError::InvalidState) => {
            conflict_response("订单状态不允许支付")
        }
        Err(_) => internal_database_response(),
    }
}

async fn refund_admin_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(order_id): Path<Uuid>,
) -> Response {
    let event_id = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("manual-refund");
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .refund_order(state.config.tenant_id, order_id, event_id)
        .await
    {
        Ok(order) => Json(json!({"id": order.id, "status": order.status})).into_response(),
        Err(cyberboard_database::DatabaseError::InvalidState) => {
            conflict_response("订单状态不允许退款")
        }
        Err(_) => internal_database_response(),
    }
}

async fn me_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    if let Err(response) = require_portal_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return Json(json!({"items": [], "total": 0, "page": 1, "pageSize": 50})).into_response();
    };
    match (database.list_orders(state.config.tenant_id, identity.user_id, 50, 0).await, database.count_orders(state.config.tenant_id, identity.user_id).await) {
        (Ok(items), Ok(total)) => Json(json!({"items": items.iter().map(|item| json!({"id":item.id,"status":item.status,"amountCents":item.amount_cents,"currency":item.currency,"createdAt":item.created_at,"plan":item.plan})).collect::<Vec<_>>(),"total":total,"page":1,"pageSize":50})).into_response(),
        _ => internal_database_response(),
    }
}

async fn me_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    if let Err(response) = require_portal_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return Json(json!({"items": [], "total": 0, "page": 1, "pageSize": 50})).into_response();
    };
    let user_id = identity.user_id;
    match (database.list_devices(state.config.tenant_id, user_id, 50, 0).await, database.count_devices(state.config.tenant_id, user_id).await) {
        (Ok(items), Ok(total)) => Json(json!({"items": items.iter().map(|item| json!({"id":item.id,"name":item.name,"lastSeenAt":item.last_seen_at,"createdAt":item.created_at,"revokedAt":item.revoked_at})).collect::<Vec<_>>(),"total":total,"page":1,"pageSize":50})).into_response(),
        _ => internal_database_response(),
    }
}

async fn me_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(identity): Extension<AuthIdentity>,
) -> Response {
    if let Err(response) = require_portal_auth(&state, &headers) {
        return response;
    }
    let Some(database) = state.database.as_ref() else {
        return Json(json!({"usedBytes": 0, "quotaBytes": 0, "todayBytes": 0, "projectedBytes": 0, "periodStart": "", "periodEnd": "", "daily": []})).into_response();
    };
    let user_id = identity.user_id;
    match database.usage_summary(state.config.tenant_id, user_id).await { Ok(usage) => Json(json!({"usedBytes":usage.used_bytes,"quotaBytes":0,"todayBytes":0,"projectedBytes":usage.used_bytes,"periodStart":usage.period_start.unwrap_or_default(),"periodEnd":usage.period_end.unwrap_or_default(),"daily":[]})).into_response(), Err(_) => internal_database_response() }
}

async fn public_subscription(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match database
        .nodes_for_subscription_token(state.config.tenant_id, &token)
        .await
    {
        Ok(nodes) if !nodes.is_empty() => {
            let outbounds: Vec<Value> = nodes.iter().map(|node| json!({"type":"socks","tag":format!("node-{}",node.id.simple()),"server":node.address,"server_port":node.port})).collect();
            let mut response = Json(json!({
                "version": 1,
                "experimental": false,
                "outbounds": outbounds,
                "route": {"final": "direct"}
            }))
            .into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            response.headers_mut().insert(
                header::REFERRER_POLICY,
                axum::http::HeaderValue::from_static("no-referrer"),
            );
            response
        }
        Ok(_) => not_found_response("订阅不存在、已过期或没有可用节点"),
        Err(_) => internal_database_response(),
    }
}

fn invalid_input_response(message: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiErrorResponse {
            code: "invalid_input",
            message,
        }),
    )
        .into_response()
}

fn conflict_response(message: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(ApiErrorResponse {
            code: "conflict",
            message,
        }),
    )
        .into_response()
}

fn feature_pending_response() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ApiErrorResponse {
            code: "feature_pending",
            message: "配置持久化接口正在接入",
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigTemplateRequest {
    name: Option<String>,
    description: Option<String>,
    core_type: Option<String>,
    core_version_range: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ConfigRevisionAction {
    expected_generation: Option<i64>,
    expected_previous_hash: Option<String>,
}

fn config_template_json(record: ConfigTemplateRecord) -> Value {
    json!({"id":record.id,"name":record.name,"description":record.description,"coreType":record.core_type,"coreVersionRange":record.core_version_range,"status":record.status,"updatedAt":record.updated_at,"updatedBy":record.updated_by})
}

fn config_revision_json(record: ConfigRevisionRecord) -> Value {
    json!({"id":record.id,"templateId":record.template_id,"nodeId":record.node_id,"nodeName":record.node_name,"generation":record.generation,"coreVersion":record.core_version,"contentHash":record.content_hash,"signatureStatus":record.signature_status,"validationStatus":record.validation_status,"publishStatus":record.publish_status,"failureReason":record.failure_reason,"createdAt":record.created_at})
}

async fn list_config_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationQuery>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let limit = pagination.bounded_limit();
    let offset = pagination.bounded_offset();
    match (db.list_config_templates(state.config.tenant_id, limit, offset).await, db.count_config_templates(state.config.tenant_id).await) {
        (Ok(items), Ok(total)) => Json(json!({"items":items.into_iter().map(config_template_json).collect::<Vec<_>>(),"total":total,"page":offset/limit+1,"pageSize":limit})).into_response(), _ => internal_database_response()
    }
}

async fn create_config_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConfigTemplateRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let input = ConfigTemplateInput {
        name: req.name.unwrap_or_default(),
        description: req.description.unwrap_or_default(),
        core_type: req.core_type.unwrap_or_else(|| "sing-box".into()),
        core_version_range: req.core_version_range.unwrap_or_else(|| "*".into()),
        status: req.status.unwrap_or_else(|| "draft".into()),
    };
    if input.name.trim().is_empty() {
        return invalid_input_response("配置模板名称不能为空");
    }
    match db
        .create_config_template(state.config.tenant_id, &input)
        .await
    {
        Ok(record) => (StatusCode::CREATED, Json(config_template_json(record))).into_response(),
        Err(error) if error.is_conflict() => conflict_response("配置模板名称已存在"),
        Err(_) => internal_database_response(),
    }
}

async fn update_config_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<ConfigTemplateRequest>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let input = ConfigTemplateUpdate {
        name: req.name,
        description: req.description,
        core_type: req.core_type,
        core_version_range: req.core_version_range,
        status: req.status,
    };
    match db
        .update_config_template(state.config.tenant_id, id, &input)
        .await
    {
        Ok(Some(record)) => Json(config_template_json(record)).into_response(),
        Ok(None) => not_found_response("配置模板不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn delete_config_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    match db.delete_config_template(state.config.tenant_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => not_found_response("配置模板不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn list_config_revisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationQuery>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let limit = pagination.bounded_limit();
    let offset = pagination.bounded_offset();
    match (db.list_config_revisions(state.config.tenant_id,limit,offset).await,db.count_config_revisions(state.config.tenant_id).await) { (Ok(items),Ok(total))=>Json(json!({"items":items.into_iter().map(config_revision_json).collect::<Vec<_>>(),"total":total,"page":offset/limit+1,"pageSize":limit})).into_response(), _=>internal_database_response() }
}

async fn publish_config_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(action): Json<ConfigRevisionAction>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let Some(generation) = action.expected_generation else {
        return invalid_input_response("expectedGeneration不能为空");
    };
    match db
        .set_config_publish_status(
            state.config.tenant_id,
            id,
            generation,
            "published",
            action.expected_previous_hash.as_deref(),
        )
        .await
    {
        Ok(Some(record)) => Json(config_revision_json(record)).into_response(),
        Ok(None) => conflict_response("配置版本 generation 冲突或不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn rollback_config_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<uuid::Uuid>,
    Json(action): Json<ConfigRevisionAction>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    let Some(db) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let Some(generation) = action.expected_generation else {
        return invalid_input_response("expectedGeneration不能为空");
    };
    match db
        .set_config_publish_status(
            state.config.tenant_id,
            id,
            generation,
            "rolled_back",
            action.expected_previous_hash.as_deref(),
        )
        .await
    {
        Ok(Some(record)) => Json(config_revision_json(record)).into_response(),
        Ok(None) => conflict_response("配置版本 generation 冲突或不存在"),
        Err(_) => internal_database_response(),
    }
}

async fn config_boundary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }
    if state.database.is_none() {
        service_unavailable_response()
    } else {
        feature_pending_response()
    }
}

async fn admin_subscriptions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationQuery>,
) -> Response {
    if let Err(response) = require_auth(&state, &headers) {
        return response;
    }

    let Some(database) = state.database.as_ref() else {
        return service_unavailable_response();
    };
    let limit = pagination.bounded_limit();
    let offset = pagination.bounded_offset();
    let items = match database
        .list_subscriptions(
            state.config.tenant_id,
            limit,
            offset,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(items) => items
            .into_iter()
            .map(|item| subscription_summary_owned(item, false))
            .collect(),
        Err(_) => return internal_database_response(),
    };
    let total = match database
        .count_subscriptions(
            state.config.tenant_id,
            pagination.search.as_deref(),
            pagination.status.as_deref(),
        )
        .await
    {
        Ok(value) => value,
        Err(_) => return internal_database_response(),
    };
    Json(ResourceListResponse {
        items,
        total,
        page: offset / limit + 1,
        page_size: limit,
    })
    .into_response()
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
    let database = if state.database.is_some() {
        "connected"
    } else {
        "memory_mode"
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
            "/api/v1/portal/subscription": {
                "get": { "operationId": "getPortalSubscription", "security": [{"portalBearerAuth": []}], "responses": { "200": { "description": "Current portal subscription", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubscriptionSummary" } } } }, "401": { "description": "Invalid portal token" }, "404": { "description": "No active subscription" }, "503": { "description": "Database unavailable" } } }
            },
            "/api/v1/portal/usage": {
                "get": { "operationId": "getPortalUsage", "security": [{"portalBearerAuth": []}], "responses": { "200": { "description": "Current portal usage", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/PortalUsage" } } } }, "401": { "description": "Invalid portal token" }, "404": { "description": "No usage available" }, "503": { "description": "Database unavailable" } } }
            },
            "/api/v1/me/orders": { "get": { "operationId":"listMyOrders", "security":[{"portalBearerAuth":[]}], "responses":{"200":{"description":"Tenant/user scoped order page"},"401":{"description":"Invalid portal token"},"501":{"description":"Database repository pending"}} } },
            "/api/v1/me/devices": { "get": { "operationId":"listMyDevices", "security":[{"portalBearerAuth":[]}], "responses":{"200":{"description":"Tenant/user scoped device page"},"401":{"description":"Invalid portal token"},"501":{"description":"Database repository pending"}} } },
            "/api/v1/me/usage": { "get": { "operationId":"getMyUsage", "security":[{"portalBearerAuth":[]}], "responses":{"200":{"description":"Tenant/user scoped usage"},"401":{"description":"Invalid portal token"},"501":{"description":"Database repository pending"}} } },
            "/subscribe/{token}": {
                "get": { "operationId": "getSubscriptionConfig", "parameters": [{"name":"token","in":"path","required":true,"schema":{"type":"string"}}], "responses": { "200": { "description": "Sing-box compatible JSON configuration" }, "404": { "description": "Subscription missing or expired" }, "503": { "description": "Database unavailable" } } }
            },
            "/api/v1/admin/dashboard": {
                "get": { "operationId": "getAdminDashboard", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Demo dashboard summary", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/DashboardSummary" } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } }
            },
            "/api/v1/admin/config-templates": { "get": {"operationId":"listConfigTemplates","security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Config templates"},"401":{"description":"Invalid token"},"503":{"description":"Database unavailable"},"501":{"description":"Repository pending"}}}, "post": {"operationId":"createConfigTemplate","security":[{"bearerAuth":[]}],"responses":{"201":{"description":"Created template"},"401":{"description":"Invalid token"},"503":{"description":"Database unavailable"},"501":{"description":"Repository pending"}}} },
            "/api/v1/admin/config-templates/{templateId}": { "patch":{"operationId":"updateConfigTemplate","security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Updated template"},"501":{"description":"Repository pending"}}}, "delete":{"operationId":"deleteConfigTemplate","security":[{"bearerAuth":[]}],"responses":{"204":{"description":"Template deleted"},"501":{"description":"Repository pending"}}} },
            "/api/v1/admin/config-revisions": { "get":{"operationId":"listConfigRevisions","security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Config revisions"},"501":{"description":"Repository pending"}}} },
            "/api/v1/admin/config-revisions/{revisionId}/publish": { "post":{"operationId":"publishConfigRevision","security":[{"bearerAuth":[]}],"responses":{"202":{"description":"Deployment queued"},"409":{"description":"Generation conflict"},"501":{"description":"Repository pending"}}} },
            "/api/v1/admin/config-revisions/{revisionId}/rollback": { "post":{"operationId":"rollbackConfigRevision","security":[{"bearerAuth":[]}],"responses":{"202":{"description":"Rollback queued"},"409":{"description":"Generation conflict"},"501":{"description":"Repository pending"}}} },
            "/api/v1/admin/nodes": {
                "get": { "operationId": "listAdminNodes", "security": [{"bearerAuth": []}], "parameters": [{"name":"page","in":"query","schema":{"type":"integer"}},{"name":"pageSize","in":"query","schema":{"type":"integer"}}], "responses": { "200": { "description": "Tenant-scoped node page", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/NodeList" } } } }, "401": { "description": "Missing or invalid bearer token" }, "503": { "description": "Database unavailable" } } },
                "post": { "operationId": "createAdminNode", "security": [{"bearerAuth": []}], "responses": { "201": { "description": "Created node" }, "401": { "description": "Missing or invalid bearer token" }, "503": { "description": "Database unavailable" } } }
            },
            "/api/v1/admin/users": {
                "get": { "operationId": "listAdminUsers", "security": [{"bearerAuth": []}], "parameters": [{"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100}},{"name":"offset","in":"query","schema":{"type":"integer","minimum":0}}], "responses": { "200": { "description": "Tenant-scoped user page", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/UserList" } } } }, "401": { "description": "Missing or invalid bearer token", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } }, "503": { "description": "Database unavailable", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } } } } },
                "post": { "operationId": "createAdminUser", "security": [{"bearerAuth": []}], "requestBody": {"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateUserRequest"}}}}, "responses": { "201": {"description":"Created user","content":{"application/json":{"schema":{"$ref":"#/components/schemas/UserSummary"}}}}, "401":{"description":"Missing or invalid bearer token"}, "503":{"description":"Database unavailable"}} }
            },
            "/api/v1/admin/users/{userId}": {
                "patch": { "operationId": "updateAdminUser", "security": [{"bearerAuth": []}], "parameters": [{"name":"userId","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}], "requestBody": {"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/UpdateUserRequest"}}}}, "responses": {"200":{"description":"Updated user","content":{"application/json":{"schema":{"$ref":"#/components/schemas/UserSummary"}}}},"401":{"description":"Missing or invalid bearer token"},"404":{"description":"User not found"},"503":{"description":"Database unavailable"}} },
                "delete": { "operationId": "deleteAdminUser", "security": [{"bearerAuth": []}], "parameters": [{"name":"userId","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}], "responses": {"204":{"description":"User deleted"},"401":{"description":"Missing or invalid bearer token"},"404":{"description":"User not found"},"503":{"description":"Database unavailable"}} }
            },
            "/api/v1/admin/subscriptions": {
                "get": { "operationId": "listAdminSubscriptions", "security": [{"bearerAuth": []}], "parameters": [{"name":"page","in":"query","schema":{"type":"integer"}},{"name":"pageSize","in":"query","schema":{"type":"integer"}}], "responses": { "200": { "description": "Tenant-scoped subscription page", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SubscriptionList" } } } }, "401": { "description": "Missing or invalid bearer token" }, "503": { "description": "Database unavailable" } } },
                "post": { "operationId": "createAdminSubscription", "security": [{"bearerAuth": []}], "responses": { "201": { "description": "Created subscription" }, "401": { "description": "Missing or invalid bearer token" }, "503": { "description": "Database unavailable" } } }
            },
            "/api/v1/admin/plans": {
                "get": { "operationId": "listAdminPlans", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Tenant-scoped plan page", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/PlanList" } } } }, "503": { "description": "Database unavailable" } } },
                "post": { "operationId": "createAdminPlan", "security": [{"bearerAuth": []}], "responses": { "201": { "description": "Created plan" }, "503": { "description": "Database unavailable" } } }
            },
            "/api/v1/admin/plans/{planId}": {
                "patch": { "operationId": "updateAdminPlan", "security": [{"bearerAuth": []}], "parameters": [{"name":"planId","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}], "responses": { "200": { "description": "Updated plan" }, "404": { "description": "Plan not found" } } },
                "delete": { "operationId": "deleteAdminPlan", "security": [{"bearerAuth": []}], "parameters": [{"name":"planId","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}], "responses": { "204": { "description": "Plan archived" }, "404": { "description": "Plan not found" } } }
            },
            "/api/v1/admin/subscriptions/{subscriptionId}": {
                "patch": { "operationId": "updateAdminSubscription", "security": [{"bearerAuth": []}], "parameters": [{"name":"subscriptionId","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}], "responses": { "200": { "description": "Updated subscription" }, "404": { "description": "Subscription not found" } } },
                "delete": { "operationId": "deleteAdminSubscription", "security": [{"bearerAuth": []}], "parameters": [{"name":"subscriptionId","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}], "responses": { "204": { "description": "Subscription revoked" }, "404": { "description": "Subscription not found" } } }
            },
            "/api/v1/admin/nodes/{nodeId}": {
                "patch": { "operationId": "updateAdminNode", "security": [{"bearerAuth": []}], "responses": { "200": { "description": "Updated node" }, "404": { "description": "Node not found" } } },
                "delete": { "operationId": "deleteAdminNode", "security": [{"bearerAuth": []}], "responses": { "204": { "description": "Node deleted" }, "404": { "description": "Node not found" } } }
            }
        },
        "securitySchemes": {
            "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "opaque" },
            "portalBearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "opaque" }
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
                        "coreVersion": { "type": "string" }, "agentVersion": { "type": "string" }, "currentConfigRevision": { "type": ["string", "null"] },
                        "latencyMs": { "type": ["integer", "null"], "format": "int64" }, "lastHeartbeatAt": { "type": ["string", "null"], "format": "date-time" }
                    }
                },
                "NodeList": {
                    "type":"object", "required":["items","total","page","pageSize"],
                    "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/NodeSummary"}},"total":{"type":"integer"},"page":{"type":"integer"},"pageSize":{"type":"integer"}}
                },
                "PlanSummary": {
                    "type":"object",
                    "required":["id","name","description","priceCents","currency","durationDays","quotaBytes","deviceLimit","status","nodeGroupIds"],
                    "properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"priceCents":{"type":"integer"},"currency":{"type":"string"},"durationDays":{"type":"integer"},"quotaBytes":{"type":"integer"},"deviceLimit":{"type":"integer"},"status":{"type":"string","enum":["active","draft","archived"]},"nodeGroupIds":{"type":"array","items":{"type":"string"}}}
                },
                "PlanList": {
                    "type":"object", "required":["items","total","page","pageSize"],
                    "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/PlanSummary"}},"total":{"type":"integer"},"page":{"type":"integer"},"pageSize":{"type":"integer"}}
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
                "UserList": {
                    "type": "object",
                    "required": ["items", "total", "page", "pageSize"],
                    "properties": { "items": {"type":"array","items":{"$ref":"#/components/schemas/UserSummary"}}, "total":{"type":"integer","format":"int64"}, "page":{"type":"integer"}, "pageSize":{"type":"integer"} }
                },
                "CreateUserRequest": {
                    "type": "object", "required": ["email", "password", "displayName"],
                    "properties": { "email":{"type":"string","format":"email"}, "password":{"type":"string","format":"password"}, "displayName":{"type":"string"} }
                },
                "UpdateUserRequest": {
                    "type": "object",
                    "properties": { "email":{"type":"string","format":"email"}, "displayName":{"type":"string"}, "status":{"type":"string","enum":["active","suspended","banned"]} }
                },
                "SubscriptionSummary": {
                    "type": "object",
                    "required": ["id", "userEmail", "plan", "status", "trafficUsedBytes", "trafficQuotaBytes", "expiresAt", "tokenHint"],
                    "properties": {
                        "id": { "type": "string" }, "userEmail": { "type": "string" }, "plan": { "type": "string" },
                        "status": { "type": "string", "enum": ["active", "pending", "expired", "revoked"] },
                        "trafficUsedBytes": { "type": "integer", "format": "int64" }, "trafficQuotaBytes": { "type": "integer", "format": "int64" },
                        "expiresAt": { "type": "string", "format": "date" }, "tokenHint": { "type": "string" }, "subscriptionUrl": { "type": ["string", "null"] }
                    }
                },
                "SubscriptionList": { "type":"object", "required":["items","total","page","pageSize"], "properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/SubscriptionSummary"}},"total":{"type":"integer"},"page":{"type":"integer"},"pageSize":{"type":"integer"}} },
                "PortalUsage": { "type":"object", "required":["usedBytes","quotaBytes","todayBytes","projectedBytes","periodStart","periodEnd","daily"], "properties":{"usedBytes":{"type":"integer"},"quotaBytes":{"type":"integer"},"todayBytes":{"type":"integer"},"projectedBytes":{"type":"integer"},"periodStart":{"type":"string"},"periodEnd":{"type":"string"},"daily":{"type":"array","items":{"type":"object"}}} }
            }
        }
    }))
}

fn router(state: AppState) -> Router {
    use axum::middleware::from_fn_with_state;

    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/openapi.json", get(openapi))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/portal-login", post(portal_login))
        .route("/subscribe/{token}", get(public_subscription));

    let portal = Router::new()
        .route("/api/v1/session", get(session))
        .route("/api/v1/portal/subscription", get(portal_subscription))
        .route("/api/v1/portal/usage", get(portal_usage))
        .route("/api/v1/me/orders", get(me_orders).post(create_my_order))
        .route("/api/v1/me/devices", get(me_devices))
        .route("/api/v1/me/usage", get(me_usage))
        .route_layer(from_fn_with_state(state.clone(), portal_auth_middleware));

    let admin = Router::new()
        .route("/api/v1/admin/dashboard", get(admin_dashboard))
        .route(
            "/api/v1/admin/nodes",
            get(admin_nodes).post(create_admin_node),
        )
        .route(
            "/api/v1/admin/nodes/{node_id}",
            patch(update_admin_node).delete(delete_admin_node),
        )
        .route(
            "/api/v1/admin/users",
            get(admin_users).post(create_admin_user),
        )
        .route(
            "/api/v1/admin/users/{user_id}",
            patch(update_admin_user).delete(delete_admin_user),
        )
        .route(
            "/api/v1/admin/plans",
            get(admin_plans).post(create_admin_plan),
        )
        .route(
            "/api/v1/admin/plans/{plan_id}",
            patch(update_admin_plan).delete(delete_admin_plan),
        )
        .route(
            "/api/v1/admin/subscriptions",
            get(admin_subscriptions).post(create_admin_subscription),
        )
        .route(
            "/api/v1/admin/subscriptions/{subscription_id}",
            patch(update_admin_subscription).delete(delete_admin_subscription),
        )
        .route(
            "/api/v1/admin/orders/{order_id}/mark-paid",
            post(mark_admin_order_paid),
        )
        .route(
            "/api/v1/admin/orders/{order_id}/refund",
            post(refund_admin_order),
        )
        .route(
            "/api/v1/admin/config-templates",
            get(list_config_templates).post(create_config_template),
        )
        .route(
            "/api/v1/admin/config-templates/{template_id}",
            patch(update_config_template).delete(delete_config_template),
        )
        .route("/api/v1/admin/config-revisions", get(list_config_revisions))
        .route(
            "/api/v1/admin/config-revisions/{revision_id}/publish",
            post(publish_config_revision),
        )
        .route(
            "/api/v1/admin/config-revisions/{revision_id}/rollback",
            post(rollback_config_revision),
        )
        .route_layer(from_fn_with_state(state.clone(), admin_auth_middleware));

    public.merge(portal).merge(admin).with_state(state)
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
    let database = if let Some(database_url) = config.database_url.as_deref() {
        let database = Database::connect(database_url).await?;
        database.migrate().await?;
        database.ensure_tenant(config.tenant_id).await?;
        Some(Arc::new(database))
    } else {
        None
    };
    let state = AppState::with_database(config, database);
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
                dev_mode: true,
                tenant_id: uuid::Uuid::from_u128(1),
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

    #[test]
    fn ordinary_user_role_cannot_satisfy_admin_login_requirement() {
        assert!(!super::role_allowed(&["user".to_owned()], true));
        assert!(super::role_allowed(&["user".to_owned()], false));
        assert!(super::role_allowed(&["admin".to_owned()], true));
        assert!(!super::role_allowed(&["admin".to_owned()], false));
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
            "/api/v1/admin/plans",
            "/api/v1/admin/subscriptions",
        ] {
            let (status, _, body) = get_json(path, Some("Bearer cyberboard-dev-token")).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["code"], "database_unavailable");
        }

        let (status, _, body) = get_json(
            "/api/v1/admin/users?limit=20&offset=0",
            Some("Bearer cyberboard-dev-token"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["code"], "database_unavailable");
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
    async fn portal_session_and_resources_use_portal_token_namespace() {
        let (status, _, body) = get_json(
            "/api/v1/session",
            Some("Bearer cyberboard-portal-dev-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], "demo-user");
        assert_eq!(body["roles"], serde_json::json!(["user"]));

        for path in ["/api/v1/portal/subscription", "/api/v1/portal/usage"] {
            let (status, _, body) =
                get_json(path, Some("Bearer cyberboard-portal-dev-token")).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["code"], "database_unavailable");
        }

        let (status, _, body) = get_json(
            "/api/v1/portal/subscription",
            Some("Bearer cyberboard-dev-token"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "invalid_token");
    }

    #[tokio::test]
    async fn user_mutations_fail_explicitly_without_database() {
        let authorization = "Bearer cyberboard-dev-token";
        let requests = [
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header(header::AUTHORIZATION, authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"new@example.com","password":"password","displayName":"New"}"#,
                ))
                .unwrap(),
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/00000000-0000-0000-0000-000000000002")
                .header(header::AUTHORIZATION, authorization)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"displayName":"Updated"}"#))
                .unwrap(),
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/admin/users/00000000-0000-0000-0000-000000000002")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .unwrap(),
        ];

        for request in requests {
            let (status, _, body) = request_json(request).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["code"], "database_unavailable");
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
        for schema in [
            "NodeList",
            "UserList",
            "PlanList",
            "SubscriptionList",
            "PortalUsage",
        ] {
            assert!(
                document["components"]["schemas"][schema].is_object(),
                "missing schema {schema}"
            );
        }
        for path in [
            "/api/v1/session",
            "/api/v1/portal/subscription",
            "/api/v1/portal/usage",
            "/api/v1/admin/dashboard",
            "/api/v1/admin/nodes",
            "/api/v1/admin/users",
            "/api/v1/admin/plans",
            "/api/v1/admin/subscriptions",
            "/api/v1/admin/plans/{planId}",
            "/api/v1/admin/nodes/{nodeId}",
            "/api/v1/admin/subscriptions/{subscriptionId}",
        ] {
            assert!(
                document["paths"][path].is_object(),
                "missing OpenAPI path {path}"
            );
        }
    }
}
