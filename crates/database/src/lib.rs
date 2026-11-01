//! PostgreSQL connection, migration, and repository boundary.
//!
//! Runtime SQL is used instead of `query!` macros so the workspace can compile
//! without a live database. Every repository method takes an explicit tenant ID
//! to keep tenant scoping visible at the call site.

use std::time::Duration;

use cyberboard_storage::{
    EIGHTH_MIGRATION, ELEVENTH_MIGRATION, FIFTH_MIGRATION, FOURTH_MIGRATION, INITIAL_MIGRATION,
    NINTH_MIGRATION, SECOND_MIGRATION, SEVENTH_MIGRATION, SIXTH_MIGRATION, TENTH_MIGRATION,
    THIRD_MIGRATION, THIRTEENTH_MIGRATION, TWELFTH_MIGRATION,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

mod admin_bootstrap;
include!("config_delivery.rs");

const CREATE_ORDER_SQL: &str = "INSERT INTO orders (tenant_id,user_id,plan_id,status,amount_cents,currency,idempotency_key) SELECT $1,$2,id,'pending',price_cents,currency,$4 FROM plans WHERE tenant_id=$1 AND id=$3 AND status='active' RETURNING id,status,amount_cents,currency,created_at::text AS created_at,paid_at::text AS paid_at, (SELECT name FROM plans WHERE tenant_id=$1 AND id=$3) AS plan";
const CREATE_ORDER_IDEMPOTENT_SQL: &str = "INSERT INTO orders (tenant_id,user_id,plan_id,status,amount_cents,currency,provider,idempotency_key) SELECT $1,$2,id,'pending',price_cents,currency,'manual',$3 FROM plans WHERE tenant_id=$1 AND id=$4 AND status='active' RETURNING id,user_id,plan_id,status,amount_cents,currency,provider,provider_payment_id,paid_at::text AS paid_at";

pub type DatabaseResult<T> = Result<T, DatabaseError>;

fn sha256_hex(payload: &[u8]) -> String {
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn deployment_status_from_phase(phase: &str) -> &'static str {
    match phase {
        "applied" => "applied",
        "rolled_back" => "rolled_back",
        _ => "failed",
    }
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

pub fn hash_session_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid payment order state")]
    InvalidState,
    #[error("purchasable plan not found")]
    PlanUnavailable,
    #[error("idempotency key parameters conflict")]
    IdempotencyConflict,
    #[error("usage payload is invalid: {0}")]
    InvalidUsagePayload(String),
    #[error("bootstrap admin email already belongs to an existing user")]
    BootstrapAdminEmailConflict,
    #[error("device limit exceeded")]
    DeviceLimitExceeded,
    #[error("configuration revision conflict: {0}")]
    ConfigConflict(&'static str),
    #[error("configuration revision not found")]
    ConfigRevisionNotFound,
    #[error("no applied rollback target")]
    NoRollbackTarget,
}

impl DatabaseError {
    pub fn is_conflict(&self) -> bool {
        match self {
            Self::IdempotencyConflict => true,
            Self::Sqlx(error) => error
                .as_database_error()
                .is_some_and(|db| db.code().as_deref() == Some("23505")),
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn create_session(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        token: &str,
        role: &str,
        ttl_seconds: i64,
    ) -> DatabaseResult<()> {
        sqlx::query("INSERT INTO sessions(tenant_id,user_id,token_hash,role,expires_at) VALUES($1,$2,$3,$4,now()+make_interval(secs=>$5))")
            .bind(tenant_id).bind(user_id).bind(hash_session_token(token)).bind(role).bind(ttl_seconds as f64).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn create_session_with_refresh(
        &self,
        input: SessionWithRefreshInput<'_>,
    ) -> DatabaseResult<()> {
        sqlx::query("INSERT INTO sessions(tenant_id,user_id,token_hash,role,expires_at,refresh_token_hash,refresh_expires_at) VALUES($1,$2,$3,$4,now()+make_interval(secs=>$5),$6,now()+make_interval(secs=>$7))")
            .bind(input.tenant_id)
            .bind(input.user_id)
            .bind(hash_session_token(input.access_token))
            .bind(input.role)
            .bind(input.access_ttl_seconds as f64)
            .bind(hash_session_token(input.refresh_token))
            .bind(input.refresh_ttl_seconds as f64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rotate_session_refresh(
        &self,
        tenant_id: Uuid,
        refresh_token: &str,
        access_token: &str,
        next_refresh_token: &str,
        access_ttl_seconds: i64,
        refresh_ttl_seconds: i64,
    ) -> DatabaseResult<Option<SessionRecord>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id,user_id,role FROM sessions WHERE tenant_id=$1 AND refresh_token_hash=$2 AND refresh_expires_at>now() AND revoked_at IS NULL FOR UPDATE")
            .bind(tenant_id)
            .bind(hash_session_token(refresh_token))
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let session_id: Uuid = row.get("id");
        sqlx::query("UPDATE sessions SET token_hash=$2,expires_at=now()+make_interval(secs=>$3),refresh_token_hash=$4,refresh_expires_at=now()+make_interval(secs=>$5),refresh_rotated_at=now() WHERE tenant_id=$1 AND id=$6")
            .bind(tenant_id)
            .bind(hash_session_token(access_token))
            .bind(access_ttl_seconds as f64)
            .bind(hash_session_token(next_refresh_token))
            .bind(refresh_ttl_seconds as f64)
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
        let result = SessionRecord {
            id: session_id,
            user_id: row.get("user_id"),
            role: row.get("role"),
            active: true,
        };
        tx.commit().await?;
        Ok(Some(result))
    }
    pub async fn find_session(
        &self,
        tenant_id: Uuid,
        token: &str,
    ) -> DatabaseResult<Option<SessionRecord>> {
        let row = sqlx::query("SELECT id,user_id,role,expires_at>now() AS active FROM sessions WHERE tenant_id=$1 AND token_hash=$2 AND revoked_at IS NULL")
            .bind(tenant_id).bind(hash_session_token(token)).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| SessionRecord {
            id: r.get("id"),
            user_id: r.get("user_id"),
            role: r.get("role"),
            active: r.get("active"),
        }))
    }
    pub async fn revoke_session(&self, tenant_id: Uuid, token: &str) -> DatabaseResult<bool> {
        let result=sqlx::query("UPDATE sessions SET revoked_at=now() WHERE tenant_id=$1 AND token_hash=$2 AND revoked_at IS NULL").bind(tenant_id).bind(hash_session_token(token)).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_user_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_token: &str,
    ) -> DatabaseResult<Vec<SessionSummaryRecord>> {
        let rows = sqlx::query(
            "SELECT id,role,issued_at::text AS issued_at,expires_at::text AS expires_at,
                    revoked_at::text AS revoked_at,
                    (revoked_at IS NULL AND expires_at > now()) AS active,
                    (token_hash=$3) AS current
             FROM sessions
             WHERE tenant_id=$1 AND user_id=$2
             ORDER BY issued_at DESC,id",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(hash_session_token(current_token))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(SessionSummaryRecord::from_row)
            .collect())
    }

    pub async fn revoke_session_by_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
    ) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at=now()
             WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn revoke_other_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_token: &str,
    ) -> DatabaseResult<u64> {
        let result = sqlx::query(
            "UPDATE sessions SET revoked_at=now()
             WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL
               AND token_hash <> $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(hash_session_token(current_token))
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
    pub async fn connect(database_url: &str) -> DatabaseResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn healthcheck(&self) -> DatabaseResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Applies the embedded initial migration once and records it in a small
    /// schema table. A later migration runner can take ownership of this table
    /// without changing the API/repository boundary.
    pub async fn migrate(&self) -> DatabaseResult<()> {
        let mut transaction = self.pool.begin().await?;
        // Serialize schema bootstrap across API and Worker processes.
        sqlx::query("SELECT pg_advisory_xact_lock(731904218661)")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS cyberboard_schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )",
        )
        .execute(&mut *transaction)
        .await?;

        let initial_applied: Option<String> = sqlx::query_scalar(
            "SELECT version FROM cyberboard_schema_migrations WHERE version = $1",
        )
        .bind("0001_initial")
        .fetch_optional(&mut *transaction)
        .await?;

        if initial_applied.is_none() {
            sqlx::raw_sql(INITIAL_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations (version) VALUES ($1)")
                .bind("0001_initial")
                .execute(&mut *transaction)
                .await?;
        }

        let second_applied: Option<String> = sqlx::query_scalar(
            "SELECT version FROM cyberboard_schema_migrations WHERE version = $1",
        )
        .bind("0002_resource_fields")
        .fetch_optional(&mut *transaction)
        .await?;
        if second_applied.is_none() {
            sqlx::raw_sql(SECOND_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations (version) VALUES ($1)")
                .bind("0002_resource_fields")
                .execute(&mut *transaction)
                .await?;
        }

        let third_applied: Option<String> = sqlx::query_scalar(
            "SELECT version FROM cyberboard_schema_migrations WHERE version = $1",
        )
        .bind("0003_control_plane_resources")
        .fetch_optional(&mut *transaction)
        .await?;
        if third_applied.is_none() {
            sqlx::raw_sql(THIRD_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations (version) VALUES ($1)")
                .bind("0003_control_plane_resources")
                .execute(&mut *transaction)
                .await?;
        }
        let fourth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0004_config_revision_fields")
                .fetch_optional(&mut *transaction)
                .await?;
        if fourth.is_none() {
            sqlx::raw_sql(FOURTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0004_config_revision_fields")
                .execute(&mut *transaction)
                .await?;
        }
        let fifth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0005_subscription_nodes")
                .fetch_optional(&mut *transaction)
                .await?;
        if fifth.is_none() {
            sqlx::raw_sql(FIFTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0005_subscription_nodes")
                .execute(&mut *transaction)
                .await?;
        }
        let sixth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0006_sessions")
                .fetch_optional(&mut *transaction)
                .await?;
        if sixth.is_none() {
            sqlx::raw_sql(SIXTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0006_sessions")
                .execute(&mut *transaction)
                .await?;
        }
        let seventh: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0007_payment_fields")
                .fetch_optional(&mut *transaction)
                .await?;
        if seventh.is_none() {
            sqlx::raw_sql(SEVENTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0007_payment_fields")
                .execute(&mut *transaction)
                .await?;
        }

        let eighth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0008_agent_control")
                .fetch_optional(&mut *transaction)
                .await?;
        if eighth.is_none() {
            sqlx::raw_sql(EIGHTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0008_agent_control")
                .execute(&mut *transaction)
                .await?;
        }

        let ninth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0009_agent_registration_token_lifecycle")
                .fetch_optional(&mut *transaction)
                .await?;
        if ninth.is_none() {
            sqlx::raw_sql(NINTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0009_agent_registration_token_lifecycle")
                .execute(&mut *transaction)
                .await?;
        }

        let tenth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0010_subscription_token_lifecycle")
                .fetch_optional(&mut *transaction)
                .await?;
        if tenth.is_none() {
            sqlx::raw_sql(TENTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0010_subscription_token_lifecycle")
                .execute(&mut *transaction)
                .await?;
        }

        let eleventh: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0011_agent_releases")
                .fetch_optional(&mut *transaction)
                .await?;
        if eleventh.is_none() {
            sqlx::raw_sql(ELEVENTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0011_agent_releases")
                .execute(&mut *transaction)
                .await?;
        }

        let twelfth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0012_session_refresh")
                .fetch_optional(&mut *transaction)
                .await?;
        if twelfth.is_none() {
            sqlx::raw_sql(TWELFTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0012_session_refresh")
                .execute(&mut *transaction)
                .await?;
        }

        let thirteenth: Option<String> =
            sqlx::query_scalar("SELECT version FROM cyberboard_schema_migrations WHERE version=$1")
                .bind("0013_config_deployment_lifecycle")
                .fetch_optional(&mut *transaction)
                .await?;
        if thirteenth.is_none() {
            sqlx::raw_sql(THIRTEENTH_MIGRATION)
                .execute(&mut *transaction)
                .await?;
            sqlx::query("INSERT INTO cyberboard_schema_migrations(version) VALUES($1)")
                .bind("0013_config_deployment_lifecycle")
                .execute(&mut *transaction)
                .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    pub async fn ensure_tenant(&self, tenant_id: Uuid) -> DatabaseResult<()> {
        sqlx::query(
            "INSERT INTO tenants (id, slug, name)
             VALUES ($1, $2, $3)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(format!("tenant-{}", tenant_id.simple()))
        .bind("Cyberboard Default Tenant")
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_user_credentials(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> DatabaseResult<Option<UserCredentials>> {
        let row = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.password_hash, u.status,
                    COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS roles
             FROM users u
             LEFT JOIN user_roles ur ON ur.tenant_id=u.tenant_id AND ur.user_id=u.id
             LEFT JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
             WHERE u.tenant_id = $1 AND lower(u.email) = lower($2)
             GROUP BY u.id, u.email, u.display_name, u.password_hash, u.status
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| UserCredentials {
            id: row.get("id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            password_hash: row.get("password_hash"),
            status: row.get("status"),
            roles: row.get("roles"),
        }))
    }

    pub async fn find_user_credentials_by_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> DatabaseResult<Option<UserCredentials>> {
        let row = sqlx::query(
            "SELECT u.id, u.email, u.display_name, u.password_hash, u.status,
                    COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS roles
             FROM users u
             LEFT JOIN user_roles ur ON ur.tenant_id=u.tenant_id AND ur.user_id=u.id
             LEFT JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
             WHERE u.tenant_id=$1 AND u.id=$2
             GROUP BY u.id, u.email, u.display_name, u.password_hash, u.status
             LIMIT 1",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| UserCredentials {
            id: row.get("id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            password_hash: row.get("password_hash"),
            status: row.get("status"),
            roles: row.get("roles"),
        }))
    }

    pub async fn update_user_password(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        password_hash: &str,
    ) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE users SET password_hash=$3,updated_at=now()
             WHERE tenant_id=$1 AND id=$2 AND status='active'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_users(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<Vec<UserRecord>> {
        let rows = sqlx::query(
            "SELECT id, email, display_name, status
             FROM users
             WHERE tenant_id = $1 AND status <> 'deleted'
               AND ($2::text IS NULL OR email ILIKE '%' || $2 || '%' OR display_name ILIKE '%' || $2 || '%')
               AND ($3::text IS NULL OR status = $3)
             ORDER BY created_at DESC, id
             LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id)
        .bind(search).bind(status).bind(limit).bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| UserRecord {
                id: row.get("id"),
                email: row.get("email"),
                display_name: row.get("display_name"),
                status: row.get("status"),
            })
            .collect())
    }

    pub async fn count_users(
        &self,
        tenant_id: Uuid,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM users WHERE tenant_id = $1 AND status <> 'deleted'
             AND ($2::text IS NULL OR email ILIKE '%' || $2 || '%' OR display_name ILIKE '%' || $2 || '%')
             AND ($3::text IS NULL OR status = $3)",
        )
        .bind(tenant_id).bind(search).bind(status)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    pub async fn dashboard_stats(&self, tenant_id: Uuid) -> DatabaseResult<DashboardStats> {
        let row = sqlx::query(
            "SELECT
                (SELECT count(*) FROM users WHERE tenant_id=$1 AND status <> 'deleted') AS users,
                (SELECT count(*) FROM subscriptions WHERE tenant_id=$1 AND status='active' AND expires_at > now()) AS active_subscriptions,
                (SELECT count(*) FROM nodes WHERE tenant_id=$1 AND status='online') AS online_nodes,
                (SELECT COALESCE(sum(download_bytes + upload_bytes), 0)::bigint FROM usage_events WHERE tenant_id=$1 AND received_at >= now() - interval '24 hours') AS traffic_bytes_24h,
                (SELECT count(*) FROM config_deployments WHERE tenant_id=$1 AND status='failed' AND updated_at >= now() - interval '24 hours') AS failed_tasks,
                now()::text AS generated_at",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(DashboardStats {
            users: row.get("users"),
            active_subscriptions: row.get("active_subscriptions"),
            online_nodes: row.get("online_nodes"),
            traffic_bytes_24h: row.get("traffic_bytes_24h"),
            failed_tasks: row.get("failed_tasks"),
            generated_at: row.get("generated_at"),
        })
    }

    pub async fn list_audit_logs(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        action: Option<&str>,
    ) -> DatabaseResult<Vec<AuditLogRecord>> {
        let rows = sqlx::query(
            "SELECT a.id,a.action,a.resource_type,a.resource_id,a.request_id,
                    a.details,a.created_at::text AS created_at,
                    a.actor_user_id,u.email AS actor_email
             FROM audit_logs a
             LEFT JOIN users u ON u.tenant_id=a.tenant_id AND u.id=a.actor_user_id
             WHERE a.tenant_id=$1
               AND ($2::text IS NULL OR a.action ILIKE '%' || $2 || '%' OR a.resource_type ILIKE '%' || $2 || '%')
               AND ($3::text IS NULL OR a.action=$3)
             ORDER BY a.created_at DESC,a.id DESC LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id).bind(search).bind(action).bind(limit).bind(offset)
        .fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(AuditLogRecord::from_row).collect())
    }

    pub async fn count_audit_logs(
        &self,
        tenant_id: Uuid,
        search: Option<&str>,
        action: Option<&str>,
    ) -> DatabaseResult<i64> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM audit_logs a
             WHERE a.tenant_id=$1
               AND ($2::text IS NULL OR a.action ILIKE '%' || $2 || '%' OR a.resource_type ILIKE '%' || $2 || '%')
               AND ($3::text IS NULL OR a.action=$3)",
        ).bind(tenant_id).bind(search).bind(action).fetch_one(&self.pool).await?)
    }

    pub async fn create_user(
        &self,
        tenant_id: Uuid,
        email: &str,
        password_hash: &str,
        display_name: &str,
    ) -> DatabaseResult<UserRecord> {
        let row = sqlx::query(
            "INSERT INTO users (tenant_id, email, password_hash, display_name)
             VALUES ($1, $2, $3, $4)
             RETURNING id, email, display_name, status",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .bind(display_name)
        .fetch_one(&self.pool)
        .await?;
        Ok(UserRecord {
            id: row.get("id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            status: row.get("status"),
        })
    }

    pub async fn update_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email: Option<&str>,
        display_name: Option<&str>,
        status: Option<&str>,
        password_hash: Option<&str>,
    ) -> DatabaseResult<Option<UserRecord>> {
        let row = sqlx::query(
            "UPDATE users
             SET email = COALESCE($3, email),
                 display_name = COALESCE($4, display_name),
                 status = COALESCE($5, status),
                 password_hash = COALESCE($6, password_hash),
                 updated_at = now()
             WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'
             RETURNING id, email, display_name, status",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(email)
        .bind(display_name)
        .bind(status)
        .bind(password_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| UserRecord {
            id: row.get("id"),
            email: row.get("email"),
            display_name: row.get("display_name"),
            status: row.get("status"),
        }))
    }

    pub async fn delete_user(&self, tenant_id: Uuid, user_id: Uuid) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE users SET status = 'deleted', updated_at = now()
             WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_plans(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<Vec<PlanRecord>> {
        let rows = sqlx::query(
            "SELECT id, name, description, price_cents, currency, duration_days,
                    traffic_quota_bytes, device_limit, status, node_group_ids
             FROM plans WHERE tenant_id = $1
               AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR description ILIKE '%' || $2 || '%')
               AND ($3::text IS NULL OR status = $3)
             ORDER BY created_at DESC, id LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id)
        .bind(search).bind(status).bind(limit).bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(PlanRecord::from_row).collect())
    }

    pub async fn count_plans(
        &self,
        tenant_id: Uuid,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM plans WHERE tenant_id = $1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR description ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR status = $3)")
                .bind(tenant_id).bind(search).bind(status)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Returns only plans that can be purchased by a portal user.
    ///
    /// Keeping this query separate from the admin listing makes the public
    /// lifecycle rule explicit and prevents callers from accidentally exposing
    /// archived plans as purchasable options.
    pub async fn list_public_plans(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> DatabaseResult<Vec<PlanRecord>> {
        self.list_plans(tenant_id, limit, offset, None, Some("active"))
            .await
    }

    pub async fn count_public_plans(&self, tenant_id: Uuid) -> DatabaseResult<i64> {
        self.count_plans(tenant_id, None, Some("active")).await
    }

    pub async fn create_plan(
        &self,
        tenant_id: Uuid,
        plan: &PlanInput,
    ) -> DatabaseResult<PlanRecord> {
        let row = sqlx::query(
            "INSERT INTO plans (tenant_id, name, description, price_cents, currency,
                    duration_days, traffic_quota_bytes, device_limit, status, node_group_ids)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
             RETURNING id, name, description, price_cents, currency, duration_days,
                       traffic_quota_bytes, device_limit, status, node_group_ids",
        )
        .bind(tenant_id)
        .bind(&plan.name)
        .bind(&plan.description)
        .bind(plan.price_cents)
        .bind(&plan.currency)
        .bind(plan.duration_days)
        .bind(plan.quota_bytes)
        .bind(plan.device_limit)
        .bind(&plan.status)
        .bind(&plan.node_group_ids)
        .fetch_one(&self.pool)
        .await?;
        Ok(PlanRecord::from_row(row))
    }

    pub async fn update_plan(
        &self,
        tenant_id: Uuid,
        plan_id: Uuid,
        plan: &PlanUpdate,
    ) -> DatabaseResult<Option<PlanRecord>> {
        let row = sqlx::query(
            "UPDATE plans SET name=COALESCE($3,name), description=COALESCE($4,description),
                    price_cents=COALESCE($5,price_cents), currency=COALESCE($6,currency),
                    duration_days=COALESCE($7,duration_days), traffic_quota_bytes=COALESCE($8,traffic_quota_bytes),
                    device_limit=COALESCE($9,device_limit), status=COALESCE($10,status),
                    node_group_ids=COALESCE($11,node_group_ids), updated_at=now()
             WHERE tenant_id=$1 AND id=$2
             RETURNING id, name, description, price_cents, currency, duration_days,
                       traffic_quota_bytes, device_limit, status, node_group_ids",
        )
        .bind(tenant_id)
        .bind(plan_id)
        .bind(&plan.name)
        .bind(&plan.description)
        .bind(plan.price_cents)
        .bind(&plan.currency)
        .bind(plan.duration_days)
        .bind(plan.quota_bytes)
        .bind(plan.device_limit)
        .bind(&plan.status)
        .bind(&plan.node_group_ids)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(PlanRecord::from_row))
    }

    pub async fn delete_plan(&self, tenant_id: Uuid, plan_id: Uuid) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE plans SET status='archived', updated_at=now()
             WHERE tenant_id=$1 AND id=$2 AND status <> 'archived'",
        )
        .bind(tenant_id)
        .bind(plan_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_nodes(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<Vec<NodeRecord>> {
        let rows = sqlx::query(
            "SELECT n.id,n.name,n.region,n.address,n.status,n.core_type,n.core_version,n.agent_version,
                    n.current_config_revision,(SELECT generation FROM config_revisions WHERE tenant_id=n.tenant_id AND id=n.current_config_revision) AS desired_generation,
                    n.applied_config_revision,n.applied_generation,n.applied_at::text AS applied_at,n.agent_core_state,
                    n.last_heartbeat_at::text AS last_heartbeat_at,n.port,n.tags
             FROM nodes n WHERE n.tenant_id=$1 AND ($2::text IS NULL OR n.name ILIKE '%' || $2 || '%' OR n.address ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR n.status=$3) ORDER BY n.created_at DESC,n.id LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id).bind(search).bind(status).bind(limit).bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(NodeRecord::from_row).collect())
    }

    pub async fn count_nodes(
        &self,
        tenant_id: Uuid,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM nodes WHERE tenant_id=$1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR address ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR status=$3)")
                .bind(tenant_id).bind(search).bind(status)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn create_node(
        &self,
        tenant_id: Uuid,
        node: &NodeInput,
    ) -> DatabaseResult<NodeRecord> {
        let row = sqlx::query(
            "INSERT INTO nodes (tenant_id,name,region,address,port,core_type,core_version,agent_version,tags)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
             RETURNING id,name,region,address,status,core_type,core_version,agent_version,
                       current_config_revision,NULL::bigint AS desired_generation,applied_config_revision,applied_generation,applied_at::text AS applied_at,agent_core_state,
                       last_heartbeat_at::text AS last_heartbeat_at,port,tags",
        )
        .bind(tenant_id)
        .bind(&node.name)
        .bind(&node.region)
        .bind(&node.address)
        .bind(node.port)
        .bind(&node.core)
        .bind(&node.core_version)
        .bind(&node.agent_version)
        .bind(&node.tags)
        .fetch_one(&self.pool)
        .await?;
        Ok(NodeRecord::from_row(row))
    }

    pub async fn update_node(
        &self,
        tenant_id: Uuid,
        node_id: Uuid,
        node: &NodeUpdate,
    ) -> DatabaseResult<Option<NodeRecord>> {
        let row = sqlx::query(
            "UPDATE nodes SET name=COALESCE($3,name),region=COALESCE($4,region),address=COALESCE($5,address),
                    port=COALESCE($6,port),core_type=COALESCE($7,core_type),core_version=COALESCE($8,core_version),
                    status=COALESCE($9,status),tags=COALESCE($10,tags),updated_at=now()
             WHERE tenant_id=$1 AND id=$2
             RETURNING id,name,region,address,status,core_type,core_version,agent_version,
                       current_config_revision,(SELECT generation FROM config_revisions WHERE tenant_id=nodes.tenant_id AND id=nodes.current_config_revision) AS desired_generation,
                       applied_config_revision,applied_generation,applied_at::text AS applied_at,agent_core_state,
                       last_heartbeat_at::text AS last_heartbeat_at,port,tags",
        )
        .bind(tenant_id).bind(node_id).bind(&node.name).bind(&node.region).bind(&node.address)
        .bind(node.port).bind(&node.core).bind(&node.core_version).bind(&node.status).bind(&node.tags)
        .fetch_optional(&self.pool).await?;
        Ok(row.map(NodeRecord::from_row))
    }

    pub async fn delete_node(&self, tenant_id: Uuid, node_id: Uuid) -> DatabaseResult<bool> {
        let result = sqlx::query("DELETE FROM nodes WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_subscriptions(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<Vec<SubscriptionRecord>> {
        let rows = sqlx::query(
            "SELECT s.id,u.email AS user_email,p.name AS plan,s.status,s.traffic_used_bytes,
                    s.traffic_quota_bytes,s.expires_at::text AS expires_at,s.subscription_token,s.subscription_token_version
             FROM subscriptions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id
             JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id
             WHERE s.tenant_id=$1 AND ($2::text IS NULL OR u.email ILIKE '%' || $2 || '%' OR p.name ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR s.status=$3) ORDER BY s.created_at DESC,s.id LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id).bind(search).bind(status).bind(limit).bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(SubscriptionRecord::from_row).collect())
    }

    pub async fn find_subscription_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> DatabaseResult<Option<SubscriptionRecord>> {
        let row = sqlx::query("SELECT s.id,u.email AS user_email,p.name AS plan,s.status,s.traffic_used_bytes,s.traffic_quota_bytes,s.expires_at::text AS expires_at,s.subscription_token,s.subscription_token_version FROM subscriptions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.status='active' ORDER BY s.created_at DESC LIMIT 1").bind(tenant_id).bind(user_id).fetch_optional(&self.pool).await?;
        Ok(row.map(SubscriptionRecord::from_row))
    }

    pub async fn count_subscriptions(
        &self,
        tenant_id: Uuid,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM subscriptions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id WHERE s.tenant_id=$1 AND ($2::text IS NULL OR u.email ILIKE '%' || $2 || '%' OR p.name ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR s.status=$3)")
                .bind(tenant_id).bind(search).bind(status)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn create_subscription(
        &self,
        tenant_id: Uuid,
        input: &SubscriptionInput,
    ) -> DatabaseResult<SubscriptionRecord> {
        let row = sqlx::query(
            "INSERT INTO subscriptions (tenant_id,user_id,plan_id,status,traffic_quota_bytes,starts_at,expires_at,subscription_token)
             SELECT $1,$2,p.id,'active',p.traffic_quota_bytes,$4::timestamptz,
                    COALESCE($5::timestamptz, COALESCE($4::timestamptz, now()) + make_interval(days => p.duration_days)),$6
             FROM plans p WHERE p.tenant_id=$1 AND p.id=$3
             RETURNING id,user_id,plan_id,status,traffic_used_bytes,traffic_quota_bytes,expires_at::text AS expires_at,subscription_token",
        ).bind(tenant_id).bind(input.user_id).bind(input.plan_id).bind(&input.starts_at).bind(&input.expires_at).bind(&input.subscription_token)
        .fetch_one(&self.pool).await?;
        let id: Uuid = row.get("id");
        self.get_subscription(tenant_id, id)
            .await?
            .ok_or_else(|| DatabaseError::Sqlx(sqlx::Error::RowNotFound))
    }

    pub async fn update_subscription(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &SubscriptionUpdate,
    ) -> DatabaseResult<Option<SubscriptionRecord>> {
        let row = sqlx::query(
            "UPDATE subscriptions SET plan_id=COALESCE($3,plan_id),status=COALESCE($4,status),
                    starts_at=COALESCE($5::timestamptz,starts_at),updated_at=now()
             WHERE tenant_id=$1 AND id=$2
             RETURNING id,user_id,plan_id,status,traffic_used_bytes,traffic_quota_bytes,expires_at::text AS expires_at,subscription_token",
        ).bind(tenant_id).bind(id).bind(input.plan_id).bind(&input.status).bind(&input.starts_at)
        .fetch_optional(&self.pool).await?;
        match row {
            Some(row) => {
                let subscription_id: Uuid = row.get("id");
                self.get_subscription(tenant_id, subscription_id).await
            }
            None => Ok(None),
        }
    }

    pub async fn delete_subscription(&self, tenant_id: Uuid, id: Uuid) -> DatabaseResult<bool> {
        let result = sqlx::query("UPDATE subscriptions SET status='revoked',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status <> 'revoked'")
            .bind(tenant_id).bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn rotate_subscription_token(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        token: &str,
        token_hash: &str,
    ) -> DatabaseResult<Option<SubscriptionRecord>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "UPDATE subscriptions
             SET subscription_token=$3, subscription_token_hash=$4,
                 subscription_token_version=subscription_token_version+1,
                 subscription_token_revoked_at=NULL, updated_at=now()
             WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND expires_at>now()
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(token)
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let subscription_id: Uuid = row.get("id");
        sqlx::query(
            "INSERT INTO audit_logs(tenant_id,actor_user_id,action,resource_type,resource_id,details)
             VALUES($1,$2,'subscription_token.rotate','subscription',$3,jsonb_build_object('tokenVersion',(SELECT subscription_token_version FROM subscriptions WHERE tenant_id=$1 AND id=$3)))",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(subscription_id)
        .execute(&mut *tx)
        .await?;
        let record = sqlx::query(
            "SELECT s.id,u.email AS user_email,p.name AS plan,s.status,s.traffic_used_bytes,
                    s.traffic_quota_bytes,s.expires_at::text AS expires_at,s.subscription_token,s.subscription_token_version
             FROM subscriptions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id
             JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id
             WHERE s.tenant_id=$1 AND s.id=$2",
        )
        .bind(tenant_id)
        .bind(subscription_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(SubscriptionRecord::from_row(record)))
    }

    pub async fn revoke_subscription_token(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> DatabaseResult<bool> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "UPDATE subscriptions SET subscription_token_revoked_at=now(),
                    status='revoked',updated_at=now()
             WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND expires_at>now()
             RETURNING id,subscription_token_version",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        let subscription_id: Uuid = row.get("id");
        let version: i64 = row.get("subscription_token_version");
        sqlx::query(
            "INSERT INTO audit_logs(tenant_id,actor_user_id,action,resource_type,resource_id,details)
             VALUES($1,$2,'subscription_token.revoke','subscription',$3,jsonb_build_object('tokenVersion',$4))",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(subscription_id)
        .bind(version)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn get_subscription(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> DatabaseResult<Option<SubscriptionRecord>> {
        let row = sqlx::query(
            "SELECT s.id,u.email AS user_email,p.name AS plan,s.status,s.traffic_used_bytes,
                    s.traffic_quota_bytes,s.expires_at::text AS expires_at,s.subscription_token,s.subscription_token_version
             FROM subscriptions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id
             JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id
             WHERE s.tenant_id=$1 AND s.id=$2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(SubscriptionRecord::from_row))
    }

    pub async fn subscription_token_active(
        &self,
        tenant_id: Uuid,
        token: &str,
    ) -> DatabaseResult<bool> {
        let active: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM subscriptions
             WHERE tenant_id=$1 AND (subscription_token_hash=encode(digest($2,'sha256'),'hex')
                 OR (subscription_token_hash IS NULL AND subscription_token=$2))
               AND status='active' AND expires_at > now() LIMIT 1",
        )
        .bind(tenant_id)
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(active.is_some())
    }

    pub async fn nodes_for_subscription_token(
        &self,
        tenant_id: Uuid,
        token: &str,
    ) -> DatabaseResult<Vec<NodeRecord>> {
        let rows = sqlx::query("SELECT n.id,n.name,n.region,n.address,n.status,n.core_type,n.core_version,n.agent_version,n.current_config_revision,last_heartbeat_at::text AS last_heartbeat_at,n.port,n.tags FROM nodes n JOIN subscription_nodes sn ON sn.tenant_id=n.tenant_id AND sn.node_id=n.id JOIN subscriptions s ON s.tenant_id=sn.tenant_id AND s.id=sn.subscription_id WHERE n.tenant_id=$1 AND (s.subscription_token_hash=encode(digest($2,'sha256'),'hex') OR (s.subscription_token_hash IS NULL AND s.subscription_token=$2)) AND s.status='active' AND s.expires_at>now() ORDER BY n.created_at,n.id")
            .bind(tenant_id).bind(token).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(NodeRecord::from_row).collect())
    }

    pub async fn list_orders(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> DatabaseResult<Vec<OrderRecord>> {
        let rows = sqlx::query("SELECT o.id,o.status,o.amount_cents,o.currency,o.created_at::text AS created_at,o.paid_at::text AS paid_at,p.name AS plan FROM orders o JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id WHERE o.tenant_id=$1 AND o.user_id=$2 ORDER BY o.created_at DESC,o.id LIMIT $3 OFFSET $4").bind(tenant_id).bind(user_id).bind(limit).bind(offset).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(OrderRecord::from_row).collect())
    }
    pub async fn count_orders(&self, tenant_id: Uuid, user_id: Uuid) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM orders WHERE tenant_id=$1 AND user_id=$2")
                .bind(tenant_id)
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn list_admin_orders(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<Vec<AdminOrderRecord>> {
        let rows = sqlx::query(
            "SELECT o.id,o.status,o.amount_cents,o.currency,
                    o.created_at::text AS created_at,o.paid_at::text AS paid_at,
                    u.id AS user_id,u.email AS user_email,p.name AS plan
             FROM orders o
             JOIN users u ON u.tenant_id=o.tenant_id AND u.id=o.user_id
             JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id
             WHERE o.tenant_id=$1
               AND ($2::text IS NULL OR u.email ILIKE '%' || $2 || '%' OR p.name ILIKE '%' || $2 || '%' OR o.id::text ILIKE '%' || $2 || '%')
               AND ($3::text IS NULL OR o.status=$3)
             ORDER BY o.created_at DESC,o.id
             LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id)
        .bind(search)
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(AdminOrderRecord::from_row).collect())
    }

    pub async fn count_admin_orders(
        &self,
        tenant_id: Uuid,
        search: Option<&str>,
        status: Option<&str>,
    ) -> DatabaseResult<i64> {
        Ok(sqlx::query_scalar(
            "SELECT count(*)
             FROM orders o
             JOIN users u ON u.tenant_id=o.tenant_id AND u.id=o.user_id
             JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id
             WHERE o.tenant_id=$1
               AND ($2::text IS NULL OR u.email ILIKE '%' || $2 || '%' OR p.name ILIKE '%' || $2 || '%' OR o.id::text ILIKE '%' || $2 || '%')
               AND ($3::text IS NULL OR o.status=$3)",
        )
        .bind(tenant_id)
        .bind(search)
        .bind(status)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn get_admin_order(
        &self,
        tenant_id: Uuid,
        order_id: Uuid,
    ) -> DatabaseResult<Option<AdminOrderRecord>> {
        let row = sqlx::query(
            "SELECT o.id,o.status,o.amount_cents,o.currency,
                    o.created_at::text AS created_at,o.paid_at::text AS paid_at,
                    u.id AS user_id,u.email AS user_email,p.name AS plan
             FROM orders o
             JOIN users u ON u.tenant_id=o.tenant_id AND u.id=o.user_id
             JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id
             WHERE o.tenant_id=$1 AND o.id=$2",
        )
        .bind(tenant_id)
        .bind(order_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AdminOrderRecord::from_row))
    }

    pub async fn create_order(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        plan_id: Uuid,
        idempotency_key: &str,
    ) -> DatabaseResult<OrderRecord> {
        if let Some(existing) = sqlx::query("SELECT o.id,o.plan_id,o.status,o.amount_cents,o.currency,o.created_at::text AS created_at,o.paid_at::text AS paid_at,p.name AS plan FROM orders o JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id WHERE o.tenant_id=$1 AND o.user_id=$2 AND o.idempotency_key=$3")
            .bind(tenant_id).bind(user_id).bind(idempotency_key).fetch_optional(&self.pool).await? {
            if existing.get::<Uuid, _>("plan_id") != plan_id {
                return Err(DatabaseError::IdempotencyConflict);
            }
            return Ok(OrderRecord::from_row(existing));
        }
        let row = sqlx::query(CREATE_ORDER_SQL)
            .bind(tenant_id)
            .bind(user_id)
            .bind(plan_id)
            .bind(idempotency_key)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::PlanUnavailable)?;
        Ok(OrderRecord::from_row(row))
    }

    pub async fn mark_order_paid_v2(
        &self,
        tenant_id: Uuid,
        order_id: Uuid,
        provider: &str,
        provider_payment_id: &str,
        event_id: &str,
    ) -> DatabaseResult<OrderRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("UPDATE orders SET status='paid',provider=$3,provider_payment_id=$4,paid_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status='pending' RETURNING id,user_id,plan_id,status,amount_cents,currency,created_at::text AS created_at")
            .bind(tenant_id).bind(order_id).bind(provider).bind(provider_payment_id).fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Err(DatabaseError::Sqlx(sqlx::Error::RowNotFound));
        };
        sqlx::query("INSERT INTO payments (tenant_id,order_id,provider,provider_payment_id,provider_event_id,status) VALUES($1,$2,$3,$4,$5,'succeeded') ON CONFLICT (tenant_id,provider,provider_event_id) DO NOTHING")
            .bind(tenant_id).bind(order_id).bind(provider).bind(provider_payment_id).bind(event_id).execute(&mut *tx).await?;
        let user_id: Uuid = row.get("user_id");
        let plan_id: Uuid = row.get("plan_id");
        sqlx::query("INSERT INTO subscriptions (tenant_id,user_id,plan_id,status,traffic_quota_bytes,starts_at,expires_at,subscription_token) SELECT $1,$2,id,'active',traffic_quota_bytes,now(),now()+make_interval(days=>duration_days),concat('cb_',replace(gen_random_uuid()::text,'-','')) FROM plans WHERE tenant_id=$1 AND id=$3")
            .bind(tenant_id).bind(user_id).bind(plan_id).execute(&mut *tx).await?;
        let result = sqlx::query("SELECT o.id,o.status,o.amount_cents,o.currency,o.created_at::text AS created_at,o.paid_at::text AS paid_at,p.name AS plan FROM orders o JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id WHERE o.tenant_id=$1 AND o.id=$2")
            .bind(tenant_id).bind(order_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(OrderRecord::from_row(result))
    }
    pub async fn list_devices(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> DatabaseResult<Vec<DeviceRecord>> {
        let rows = sqlx::query("SELECT id,name,last_seen_at::text AS last_seen_at,created_at::text AS created_at,revoked_at::text AS revoked_at FROM devices WHERE tenant_id=$1 AND user_id=$2 ORDER BY created_at DESC,id LIMIT $3 OFFSET $4").bind(tenant_id).bind(user_id).bind(limit).bind(offset).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(DeviceRecord::from_row).collect())
    }

    pub async fn register_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        name: &str,
        fingerprint_hash: &str,
    ) -> DatabaseResult<DeviceRecord> {
        let mut tx = self.pool.begin().await?;
        if let Some(row) = sqlx::query("UPDATE devices SET name=$4,last_seen_at=now(),revoked_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND fingerprint_hash=$3 RETURNING id,name,last_seen_at::text AS last_seen_at,created_at::text AS created_at,revoked_at::text AS revoked_at")
            .bind(tenant_id).bind(user_id).bind(fingerprint_hash).bind(name)
            .fetch_optional(&mut *tx).await? {
            tx.commit().await?;
            return Ok(DeviceRecord::from_row(row));
        }
        let limit: i64 = sqlx::query_scalar("SELECT COALESCE((SELECT p.device_limit FROM subscriptions s JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.status='active' AND s.expires_at>now() ORDER BY s.created_at DESC LIMIT 1),0)")
            .bind(tenant_id).bind(user_id).fetch_one(&mut *tx).await?;
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM devices WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        if limit <= 0 || active >= limit {
            tx.rollback().await?;
            return Err(DatabaseError::DeviceLimitExceeded);
        }
        let row = sqlx::query("INSERT INTO devices(tenant_id,user_id,name,fingerprint_hash,last_seen_at) VALUES($1,$2,$3,$4,now()) RETURNING id,name,last_seen_at::text AS last_seen_at,created_at::text AS created_at,revoked_at::text AS revoked_at")
            .bind(tenant_id).bind(user_id).bind(name).bind(fingerprint_hash).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(DeviceRecord::from_row(row))
    }
    pub async fn count_devices(&self, tenant_id: Uuid, user_id: Uuid) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM devices WHERE tenant_id=$1 AND user_id=$2")
                .bind(tenant_id)
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn revoke_device(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        device_id: Uuid,
    ) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE devices SET revoked_at=now()
             WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn usage_summary(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> DatabaseResult<UsageRecord> {
        let row = sqlx::query("SELECT COALESCE(sum(download_bytes+upload_bytes),0)::bigint AS used_bytes,min(window_start)::text AS period_start,max(window_end)::text AS period_end FROM usage_events WHERE tenant_id=$1 AND user_id=$2").bind(tenant_id).bind(user_id).fetch_one(&self.pool).await?;
        Ok(UsageRecord {
            used_bytes: row.get("used_bytes"),
            period_start: row.try_get("period_start").ok(),
            period_end: row.try_get("period_end").ok(),
        })
    }

    /// Rebuilds usage buckets and synchronizes subscription lifecycle state.
    ///
    /// Raw usage events are append-only, so the bucket values are overwritten
    /// from the source of truth on every run. This makes retries safe and
    /// avoids double counting after a worker restart.
    pub async fn run_usage_maintenance(
        &self,
        tenant_id: Uuid,
    ) -> DatabaseResult<UsageMaintenanceStats> {
        let mut transaction = self.pool.begin().await?;
        let bucket_result = sqlx::query(
            "WITH aggregates AS (
                 SELECT tenant_id,
                        user_id,
                        date_trunc('hour', window_start) AS bucket_start,
                        date_trunc('hour', window_start) + interval '1 hour' AS bucket_end,
                        COALESCE(sum(download_bytes), 0)::bigint AS download_bytes,
                        COALESCE(sum(upload_bytes), 0)::bigint AS upload_bytes,
                        count(*)::bigint AS event_count,
                        min(received_at) AS first_received_at,
                        max(received_at) AS last_received_at
                 FROM usage_events
                 WHERE tenant_id=$1 AND user_id IS NOT NULL
                 GROUP BY tenant_id, user_id, date_trunc('hour', window_start)
             )
             INSERT INTO usage_buckets (
                 tenant_id, user_id, bucket_start, bucket_end,
                 download_bytes, upload_bytes, event_count,
                 first_received_at, last_received_at
             )
             SELECT tenant_id, user_id, bucket_start, bucket_end,
                    download_bytes, upload_bytes, event_count,
                    first_received_at, last_received_at
             FROM aggregates
             ON CONFLICT (tenant_id, user_id, bucket_start) DO UPDATE SET
                 bucket_end=EXCLUDED.bucket_end,
                 download_bytes=EXCLUDED.download_bytes,
                 upload_bytes=EXCLUDED.upload_bytes,
                 event_count=EXCLUDED.event_count,
                 first_received_at=EXCLUDED.first_received_at,
                 last_received_at=EXCLUDED.last_received_at",
        )
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;

        let usage_result = sqlx::query(
            "UPDATE subscriptions AS s
             SET traffic_used_bytes=COALESCE((
                 SELECT sum(e.download_bytes + e.upload_bytes)::bigint
                 FROM usage_events AS e
                 WHERE e.tenant_id=s.tenant_id
                   AND e.subscription_id=s.id
             ), 0), updated_at=now()
             WHERE s.tenant_id=$1",
        )
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;

        let activated = sqlx::query(
            "UPDATE subscriptions
             SET status='active', updated_at=now()
             WHERE tenant_id=$1 AND status='pending'
               AND (starts_at IS NULL OR starts_at <= now())
               AND expires_at > now()",
        )
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;

        let expired = sqlx::query(
            "UPDATE subscriptions
             SET status='expired', updated_at=now()
             WHERE tenant_id=$1 AND status='active' AND expires_at <= now()",
        )
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(UsageMaintenanceStats {
            buckets_upserted: bucket_result.rows_affected(),
            subscriptions_recalculated: usage_result.rows_affected(),
            subscriptions_activated: activated.rows_affected(),
            subscriptions_expired: expired.rows_affected(),
        })
    }

    pub async fn list_config_templates(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> DatabaseResult<Vec<ConfigTemplateRecord>> {
        let rows = sqlx::query("SELECT id,name,description,core_type,core_version_range,status,updated_at::text AS updated_at,COALESCE(updated_by::text,'') AS updated_by FROM config_templates WHERE tenant_id=$1 ORDER BY updated_at DESC,id LIMIT $2 OFFSET $3")
            .bind(tenant_id).bind(limit).bind(offset).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(ConfigTemplateRecord::from_row)
            .collect())
    }

    pub async fn count_config_templates(&self, tenant_id: Uuid) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM config_templates WHERE tenant_id=$1")
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn create_config_template(
        &self,
        tenant_id: Uuid,
        input: &ConfigTemplateInput,
    ) -> DatabaseResult<ConfigTemplateRecord> {
        let row = sqlx::query("INSERT INTO config_templates (tenant_id,name,description,core_type,core_version_range,content,status) VALUES ($1,$2,$3,$4,$5,'{}'::jsonb,$6) RETURNING id,name,description,core_type,core_version_range,status,updated_at::text AS updated_at,'' AS updated_by")
            .bind(tenant_id).bind(&input.name).bind(&input.description).bind(&input.core_type).bind(&input.core_version_range).bind(&input.status).fetch_one(&self.pool).await?;
        Ok(ConfigTemplateRecord::from_row(row))
    }

    pub async fn update_config_template(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &ConfigTemplateUpdate,
    ) -> DatabaseResult<Option<ConfigTemplateRecord>> {
        let row = sqlx::query("UPDATE config_templates SET name=COALESCE($3,name),description=COALESCE($4,description),core_type=COALESCE($5,core_type),core_version_range=COALESCE($6,core_version_range),status=COALESCE($7,status),updated_at=now() WHERE tenant_id=$1 AND id=$2 RETURNING id,name,description,core_type,core_version_range,status,updated_at::text AS updated_at,'' AS updated_by")
            .bind(tenant_id).bind(id).bind(&input.name).bind(&input.description).bind(&input.core_type).bind(&input.core_version_range).bind(&input.status).fetch_optional(&self.pool).await?;
        Ok(row.map(ConfigTemplateRecord::from_row))
    }

    pub async fn delete_config_template(&self, tenant_id: Uuid, id: Uuid) -> DatabaseResult<bool> {
        let result = sqlx::query("UPDATE config_templates SET status='archived',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status <> 'archived'").bind(tenant_id).bind(id).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list_config_revisions(
        &self,
        input: ConfigRevisionListInput<'_>,
    ) -> DatabaseResult<Vec<ConfigRevisionRecord>> {
        let rows = sqlx::query("SELECT r.id,COALESCE(r.template_id::text,'') AS template_id,r.node_id,n.name AS node_name,r.generation,r.core_version,r.content_hash,CASE WHEN r.signature='' THEN 'pending' ELSE 'valid' END AS signature_status,r.validation_status,r.publish_status,r.failure_reason,r.created_at::text AS created_at,d.status AS deployment_status,d.kind AS deployment_kind,d.error_code AS deployment_error_code,d.error_message AS deployment_error_message,d.updated_at::text AS deployment_updated_at,r.rollback_of FROM config_revisions r JOIN nodes n ON n.tenant_id=r.tenant_id AND n.id=r.node_id LEFT JOIN LATERAL (SELECT status,kind,error_code,error_message,updated_at FROM config_deployments WHERE tenant_id=r.tenant_id AND config_revision_id=r.id ORDER BY created_at DESC,id DESC LIMIT 1) d ON TRUE WHERE r.tenant_id=$1 AND ($2::uuid IS NULL OR r.node_id=$2) AND ($3::text IS NULL OR r.publish_status=$3) AND ($4::text IS NULL OR n.name ILIKE '%' || $4 || '%' OR r.content_hash ILIKE '%' || $4 || '%' OR r.core_version ILIKE '%' || $4 || '%') ORDER BY r.created_at DESC,r.id LIMIT $5 OFFSET $6")
            .bind(input.tenant_id).bind(input.node_id).bind(input.status).bind(input.search).bind(input.limit).bind(input.offset).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(ConfigRevisionRecord::from_row)
            .collect())
    }

    pub async fn create_config_revision(
        &self,
        input: ConfigRevisionCreateInput<'_>,
    ) -> DatabaseResult<Option<ConfigRevisionRecord>> {
        let row = sqlx::query("INSERT INTO config_revisions (tenant_id,template_id,node_id,generation,core_type,core_version,content_hash,signature,validation_status,publish_status,payload) SELECT $1,$2,$3,$4,t.core_type,$5,$6,'','validated','draft',$7 FROM config_templates t JOIN nodes n ON n.tenant_id=$1 AND n.id=$3 WHERE t.tenant_id=$1 AND t.id=$2 AND t.status <> 'archived' RETURNING id,COALESCE(template_id::text,'') AS template_id,node_id,generation,core_version,content_hash,'pending' AS signature_status,validation_status,publish_status,failure_reason,created_at::text AS created_at")
            .bind(input.tenant_id).bind(input.template_id).bind(input.node_id).bind(input.generation).bind(input.core_version).bind(input.content_hash).bind(input.payload).fetch_optional(&self.pool).await?;
        Ok(row.map(ConfigRevisionRecord::from_row))
    }

    pub async fn config_revision_for_signing(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> DatabaseResult<Option<ConfigRevisionSigningRecord>> {
        let row = sqlx::query(
            "SELECT node_id,generation,core_type,core_version,content_hash,payload
             FROM config_revisions WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| ConfigRevisionSigningRecord {
            node_id: row.get("node_id"),
            generation: row.get("generation"),
            core_type: row.get("core_type"),
            core_version: row.get("core_version"),
            content_hash: row.get("content_hash"),
            payload: row.get("payload"),
        }))
    }

    pub async fn count_config_revisions(
        &self,
        input: ConfigRevisionListInput<'_>,
    ) -> DatabaseResult<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM config_revisions r JOIN nodes n ON n.tenant_id=r.tenant_id AND n.id=r.node_id WHERE r.tenant_id=$1 AND ($2::uuid IS NULL OR r.node_id=$2) AND ($3::text IS NULL OR r.publish_status=$3) AND ($4::text IS NULL OR n.name ILIKE '%' || $4 || '%' OR r.content_hash ILIKE '%' || $4 || '%' OR r.core_version ILIKE '%' || $4 || '%')")
            .bind(input.tenant_id).bind(input.node_id).bind(input.status).bind(input.search)
            .fetch_one(&self.pool).await?)
    }

    pub async fn publish_config_revision(
        &self,
        input: ConfigPublishInput<'_>,
    ) -> DatabaseResult<Option<ConfigRevisionRecord>> {
        let mut tx = self.pool.begin().await?;
        let revision = sqlx::query(
            "SELECT id,template_id,node_id,generation,core_version,content_hash,validation_status,publish_status,failure_reason,created_at::text AS created_at
             FROM config_revisions WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(input.revision_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(revision) = revision else {
            tx.rollback().await?;
            return Ok(None);
        };
        let node_id: Uuid = revision.get("node_id");
        let node = sqlx::query(
            "SELECT current_config_revision FROM nodes WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(input.tenant_id)
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(node) = node else {
            tx.rollback().await?;
            return Ok(None);
        };
        let current_id: Option<Uuid> = node.get("current_config_revision");
        let current = if let Some(current_id) = current_id {
            sqlx::query("SELECT id,generation,content_hash FROM config_revisions WHERE tenant_id=$1 AND id=$2")
                .bind(input.tenant_id).bind(current_id).fetch_optional(&mut *tx).await?
        } else {
            None
        };
        let generation: i64 = revision.get("generation");
        let validation: String = revision.get("validation_status");
        let publish_status: String = revision.get("publish_status");
        let conflict = if generation != input.expected_generation {
            Some("generation_mismatch")
        } else if validation != "validated" {
            Some("not_validated")
        } else if publish_status != "draft" {
            Some("already_published")
        } else if current
            .as_ref()
            .is_some_and(|row| generation <= row.get::<i64, _>("generation"))
        {
            Some("stale_generation")
        } else if input.expected_previous_hash.is_some_and(|expected| {
            current
                .as_ref()
                .and_then(|row| row.try_get::<String, _>("content_hash").ok())
                .unwrap_or_default()
                != expected
        }) {
            Some("previous_hash_mismatch")
        } else {
            None
        };
        if let Some(code) = conflict {
            tx.rollback().await?;
            return Err(DatabaseError::ConfigConflict(code));
        }
        sqlx::query("UPDATE config_revisions SET publish_status='published',failure_reason=NULL,signature=$3 WHERE tenant_id=$1 AND id=$2")
            .bind(input.tenant_id).bind(input.revision_id).bind(input.signed_envelope).execute(&mut *tx).await?;
        sqlx::query("UPDATE nodes SET current_config_revision=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2")
            .bind(input.tenant_id).bind(node_id).bind(input.revision_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO config_deployments(tenant_id,config_revision_id,node_id,kind,status,expected_generation,actor_user_id) VALUES($1,$2,$3,'publish','pending',$4,$5)")
            .bind(input.tenant_id).bind(input.revision_id).bind(node_id).bind(generation).bind(input.actor_user_id).execute(&mut *tx).await?;
        let details = serde_json::json!({"nodeId":node_id,"generation":generation,"contentHash":revision.get::<String,_>("content_hash"),"previousRevisionId":current_id});
        Self::insert_audit_in_tx(
            &mut tx,
            input.tenant_id,
            input.actor_user_id,
            "config.publish",
            "config_revision",
            input.revision_id,
            &details,
        )
        .await?;
        let row = sqlx::query("SELECT r.id,COALESCE(r.template_id::text,'') AS template_id,r.node_id,n.name AS node_name,r.generation,r.core_version,r.content_hash,CASE WHEN r.signature='' THEN 'pending' ELSE 'valid' END AS signature_status,r.validation_status,r.publish_status,r.failure_reason,r.created_at::text AS created_at,r.rollback_of,(SELECT status FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_status,(SELECT kind FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_kind,(SELECT error_code FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_error_code,(SELECT error_message FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_error_message,(SELECT updated_at::text FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_updated_at FROM config_revisions r JOIN nodes n ON n.tenant_id=r.tenant_id AND n.id=r.node_id WHERE r.tenant_id=$1 AND r.id=$2")
            .bind(input.tenant_id).bind(input.revision_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(ConfigRevisionRecord::from_row(row)))
    }

    pub async fn insert_audit_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        actor_user_id: Uuid,
        action: &str,
        resource_type: &str,
        resource_id: Uuid,
        details: &serde_json::Value,
    ) -> DatabaseResult<()> {
        sqlx::query("INSERT INTO audit_logs(tenant_id,actor_user_id,action,resource_type,resource_id,details) VALUES($1,NULLIF($2,$3),$4,$5,$6,$7)")
            .bind(tenant_id).bind(actor_user_id).bind(Uuid::nil()).bind(action).bind(resource_type).bind(resource_id).bind(details)
            .execute(&mut **tx).await?;
        Ok(())
    }

    pub async fn rollback_config_revision(
        &self,
        input: ConfigRollbackInput<'_>,
    ) -> DatabaseResult<Option<ConfigRevisionRecord>> {
        let mut tx = self.pool.begin().await?;
        let node_row = sqlx::query("SELECT node_id,current_config_revision FROM nodes n JOIN config_revisions r ON r.tenant_id=n.tenant_id AND r.node_id=n.id WHERE n.tenant_id=$1 AND n.current_config_revision=$2 FOR UPDATE OF n")
            .bind(input.tenant_id).bind(input.revision_id).fetch_optional(&mut *tx).await?;
        let Some(node_row) = node_row else {
            tx.rollback().await?;
            return Err(DatabaseError::ConfigConflict("not_current_desired"));
        };
        let node_id: Uuid = node_row.get("node_id");
        let current = sqlx::query(
            "SELECT generation,publish_status FROM config_revisions WHERE tenant_id=$1 AND id=$2",
        )
        .bind(input.tenant_id)
        .bind(input.revision_id)
        .fetch_one(&mut *tx)
        .await?;
        let from_generation: i64 = current.get("generation");
        if from_generation != input.expected_generation {
            tx.rollback().await?;
            return Err(DatabaseError::ConfigConflict("generation_mismatch"));
        }
        if current.get::<String, _>("publish_status") != "published" {
            tx.rollback().await?;
            return Err(DatabaseError::ConfigConflict("not_published"));
        }
        let target = sqlx::query("SELECT r.id,r.generation,r.template_id,r.core_type,r.core_version,r.payload,r.content_hash FROM config_revisions r WHERE r.tenant_id=$1 AND r.node_id=$2 AND r.generation<$3 AND (SELECT d.status FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC LIMIT 1)='applied' ORDER BY r.generation DESC LIMIT 1")
            .bind(input.tenant_id).bind(node_id).bind(from_generation).fetch_optional(&mut *tx).await?;
        let Some(target) = target else {
            tx.rollback().await?;
            return Err(DatabaseError::NoRollbackTarget);
        };
        let target_id: Uuid = target.get("id");
        let max_generation: i64 = sqlx::query_scalar("SELECT COALESCE(max(generation),0) FROM config_revisions WHERE tenant_id=$1 AND node_id=$2")
            .bind(input.tenant_id).bind(node_id).fetch_one(&mut *tx).await?;
        let new_generation = max_generation + 1;
        let target_payload: serde_json::Value = target.get("payload");
        let target_bytes = serde_json::to_vec(&target_payload).unwrap_or_default();
        let target_hash: String = target.get("content_hash");
        if sha256_hex(&target_bytes) != target_hash {
            tx.rollback().await?;
            return Err(DatabaseError::ConfigConflict(
                "rollback_target_hash_mismatch",
            ));
        }
        let signed_envelope = (input.sign)(node_id, new_generation as u64, target_bytes);
        let new_id: Uuid = sqlx::query_scalar("INSERT INTO config_revisions(tenant_id,template_id,node_id,generation,core_type,core_version,content_hash,signature,validation_status,publish_status,payload,rollback_of) SELECT $1,template_id,node_id,$2,core_type,core_version,content_hash,$3,'validated','published',payload,$4 FROM config_revisions WHERE tenant_id=$1 AND id=$4 RETURNING id")
            .bind(input.tenant_id).bind(new_generation).bind(signed_envelope).bind(target_id).fetch_one(&mut *tx).await?;
        sqlx::query(
            "UPDATE config_revisions SET publish_status='rolled_back' WHERE tenant_id=$1 AND id=$2",
        )
        .bind(input.tenant_id)
        .bind(input.revision_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE nodes SET current_config_revision=$3,updated_at=now() WHERE tenant_id=$1 AND id=$2")
            .bind(input.tenant_id).bind(node_id).bind(new_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO config_deployments(tenant_id,config_revision_id,node_id,kind,status,expected_generation,actor_user_id) VALUES($1,$2,$3,'rollback','pending',$4,$5)")
            .bind(input.tenant_id).bind(new_id).bind(node_id).bind(new_generation).bind(input.actor_user_id).execute(&mut *tx).await?;
        let details = serde_json::json!({"nodeId":node_id,"fromRevisionId":input.revision_id,"fromGeneration":from_generation,"targetRevisionId":target_id,"targetGeneration":target.get::<i64,_>("generation"),"newRevisionId":new_id,"newGeneration":new_generation,"reason":input.reason});
        Self::insert_audit_in_tx(
            &mut tx,
            input.tenant_id,
            input.actor_user_id,
            "config.rollback",
            "config_revision",
            new_id,
            &details,
        )
        .await?;
        let row = sqlx::query("SELECT r.id,COALESCE(r.template_id::text,'') AS template_id,r.node_id,n.name AS node_name,r.generation,r.core_version,r.content_hash,CASE WHEN r.signature='' THEN 'pending' ELSE 'valid' END AS signature_status,r.validation_status,r.publish_status,r.failure_reason,r.created_at::text AS created_at,r.rollback_of,(SELECT status FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_status,(SELECT kind FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_kind,(SELECT error_code FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_error_code,(SELECT error_message FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_error_message,(SELECT updated_at::text FROM config_deployments d WHERE d.tenant_id=r.tenant_id AND d.config_revision_id=r.id ORDER BY d.created_at DESC,d.id DESC LIMIT 1) AS deployment_updated_at FROM config_revisions r JOIN nodes n ON n.tenant_id=r.tenant_id AND n.id=r.node_id WHERE r.tenant_id=$1 AND r.id=$2")
            .bind(input.tenant_id).bind(new_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(Some(ConfigRevisionRecord::from_row(row)))
    }

    #[deprecated(note = "use publish_config_revision or rollback_config_revision")]
    pub async fn set_config_publish_status(
        &self,
        _tenant_id: Uuid,
        _id: Uuid,
        _expected_generation: i64,
        _status: &str,
        _expected_previous_hash: Option<&str>,
        _signed_envelope: Option<&str>,
    ) -> DatabaseResult<Option<ConfigRevisionRecord>> {
        Err(DatabaseError::ConfigConflict("legacy API is disabled"))
    }

    pub async fn create_order_idempotent(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        plan_id: Uuid,
        idempotency_key: &str,
    ) -> DatabaseResult<PaymentOrderRecord> {
        if let Some(row) = sqlx::query("SELECT id,user_id,plan_id,status,amount_cents,currency,provider,provider_payment_id,paid_at::text AS paid_at FROM orders WHERE tenant_id=$1 AND user_id=$2 AND idempotency_key=$3")
            .bind(tenant_id).bind(user_id).bind(idempotency_key).fetch_optional(&self.pool).await? {
            if row.get::<Uuid, _>("plan_id") != plan_id {
                return Err(DatabaseError::IdempotencyConflict);
            }
            return Ok(PaymentOrderRecord::from_row(row));
        }
        let row = sqlx::query(CREATE_ORDER_IDEMPOTENT_SQL)
            .bind(tenant_id)
            .bind(user_id)
            .bind(idempotency_key)
            .bind(plan_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DatabaseError::PlanUnavailable)?;
        Ok(PaymentOrderRecord::from_row(row))
    }

    pub async fn mark_order_paid(
        &self,
        tenant_id: Uuid,
        order_id: Uuid,
        provider_event_id: &str,
    ) -> DatabaseResult<PaymentOrderRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id,user_id,plan_id,status,amount_cents,currency,provider,provider_payment_id,paid_at::text AS paid_at FROM orders WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(tenant_id).bind(order_id).fetch_one(&mut *tx).await?;
        let current = PaymentOrderRecord::from_row(row);
        if current.status == "paid" {
            tx.commit().await?;
            return Ok(current);
        }
        if current.status != "pending" {
            tx.rollback().await?;
            return Err(DatabaseError::InvalidState);
        }
        sqlx::query("INSERT INTO payments (tenant_id,order_id,provider,provider_payment_id,provider_event_id,status,raw_event) VALUES ($1,$2,'manual',$3,$4,'succeeded','{}'::jsonb) ON CONFLICT (tenant_id,provider,provider_event_id) DO NOTHING").bind(tenant_id).bind(order_id).bind(format!("manual-{order_id}")).bind(provider_event_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE orders SET status='paid',provider_payment_id=$3,paid_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(order_id).bind(format!("manual-{order_id}")).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO subscriptions (tenant_id,user_id,plan_id,status,traffic_quota_bytes,starts_at,expires_at,subscription_token) SELECT $1,o.user_id,o.plan_id,'active',p.traffic_quota_bytes,now(),now()+make_interval(days=>p.duration_days),concat('cb_',replace(gen_random_uuid()::text,'-','')) FROM orders o JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id WHERE o.tenant_id=$1 AND o.id=$2").bind(tenant_id).bind(order_id).execute(&mut *tx).await?;
        let updated = sqlx::query("SELECT id,user_id,plan_id,status,amount_cents,currency,provider,provider_payment_id,paid_at::text AS paid_at FROM orders WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(order_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(PaymentOrderRecord::from_row(updated))
    }

    pub async fn refund_order(
        &self,
        tenant_id: Uuid,
        order_id: Uuid,
        provider_event_id: &str,
    ) -> DatabaseResult<PaymentOrderRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT id,user_id,plan_id,status,amount_cents,currency,provider,provider_payment_id,paid_at::text AS paid_at FROM orders WHERE tenant_id=$1 AND id=$2 FOR UPDATE").bind(tenant_id).bind(order_id).fetch_one(&mut *tx).await?;
        let current = PaymentOrderRecord::from_row(row);
        if current.status == "refunded" {
            tx.commit().await?;
            return Ok(current);
        }
        if current.status != "paid" {
            tx.rollback().await?;
            return Err(DatabaseError::InvalidState);
        }
        sqlx::query("INSERT INTO payments (tenant_id,order_id,provider,provider_payment_id,provider_event_id,status,raw_event) VALUES ($1,$2,'manual',$3,$4,'refunded','{}'::jsonb) ON CONFLICT (tenant_id,provider,provider_event_id) DO NOTHING").bind(tenant_id).bind(order_id).bind(current.provider_payment_id.clone()).bind(provider_event_id).execute(&mut *tx).await?;
        sqlx::query(
            "UPDATE orders SET status='refunded',updated_at=now() WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(order_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE subscriptions SET status='revoked',updated_at=now() WHERE tenant_id=$1 AND user_id=$2 AND plan_id=$3 AND status='active'").bind(tenant_id).bind(current.user_id).bind(current.plan_id).execute(&mut *tx).await?;
        let updated = sqlx::query("SELECT id,user_id,plan_id,status,amount_cents,currency,provider,provider_payment_id,paid_at::text AS paid_at FROM orders WHERE tenant_id=$1 AND id=$2").bind(tenant_id).bind(order_id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(PaymentOrderRecord::from_row(updated))
    }

    pub async fn register_agent(
        &self,
        tenant_id: Uuid,
        registration_token: &str,
        public_key: &str,
        agent_version: &str,
        platform: &str,
        architecture: &str,
    ) -> DatabaseResult<Option<AgentRegistrationRecord>> {
        let Some((node_text, _secret)) = registration_token.split_once(':') else {
            return Ok(None);
        };
        let Ok(node_id) = Uuid::parse_str(node_text) else {
            return Ok(None);
        };
        let token_hash = hash_session_token(registration_token);
        let agent_id = format!("agent-{}", Uuid::new_v4().simple());
        let row = sqlx::query(
            "UPDATE nodes
             SET agent_id=$4, agent_registration_token_hash=NULL,
                 agent_registration_token_created_at=NULL,
                 agent_registration_token_expires_at=NULL,
                 agent_registration_token_revoked_at=NULL,
                 agent_public_key=$5, agent_platform=$6, agent_architecture=$7,
                 agent_version=$8, status='online', last_heartbeat_at=now(), updated_at=now()
             WHERE tenant_id=$1 AND id=$2 AND agent_registration_token_hash=$3
               AND agent_registration_token_expires_at > now()
             RETURNING id,agent_id,agent_version,agent_platform,agent_architecture",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(token_hash)
        .bind(&agent_id)
        .bind(public_key)
        .bind(platform)
        .bind(architecture)
        .bind(agent_version)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| AgentRegistrationRecord {
            node_id: row.get("id"),
            agent_id: row.get("agent_id"),
            agent_version: row.get("agent_version"),
            platform: row.get("agent_platform"),
            architecture: row.get("agent_architecture"),
        }))
    }

    pub async fn issue_agent_registration_token(
        &self,
        tenant_id: Uuid,
        node_id: Uuid,
        token_hash: &str,
        created_at_unix: i64,
        expires_at_unix: i64,
    ) -> DatabaseResult<Option<bool>> {
        let mut tx = self.pool.begin().await?;
        let previous: Option<bool> = sqlx::query_scalar(
            "SELECT agent_registration_token_hash IS NOT NULL
             FROM nodes WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(previous) = previous else {
            tx.rollback().await?;
            return Ok(None);
        };
        sqlx::query(
            "UPDATE nodes SET agent_registration_token_hash=$3,
                    agent_registration_token_created_at=to_timestamp($4),
                    agent_registration_token_expires_at=to_timestamp($5),
                    agent_registration_token_revoked_at=NULL,
                    updated_at=now()
             WHERE tenant_id=$1 AND id=$2",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(token_hash)
        .bind(created_at_unix)
        .bind(expires_at_unix)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(previous))
    }

    pub async fn revoke_agent_registration_token(
        &self,
        tenant_id: Uuid,
        node_id: Uuid,
    ) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE nodes SET agent_registration_token_hash=NULL,
                    agent_registration_token_expires_at=NULL,
                    agent_registration_token_revoked_at=now(),
                    updated_at=now()
             WHERE tenant_id=$1 AND id=$2 AND agent_registration_token_hash IS NOT NULL",
        )
        .bind(tenant_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn update_agent_heartbeat(
        &self,
        tenant_id: Uuid,
        agent_id: &str,
        node_id: Uuid,
        heartbeat: &AgentHeartbeatInput,
    ) -> DatabaseResult<bool> {
        let result = sqlx::query(
            "UPDATE nodes SET status='online',agent_version=$4,agent_platform=$5,
                    agent_architecture=$6,agent_core_state=$7,agent_memory_bytes=$8,
                    agent_disk_free_bytes=$9,agent_cpu_percent=$10,
                    current_config_revision=COALESCE(current_config_revision,current_config_revision),
                    last_heartbeat_at=now(),updated_at=now()
             WHERE tenant_id=$1 AND id=$2 AND agent_id=$3",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(agent_id)
        .bind(&heartbeat.agent_version)
        .bind(&heartbeat.platform)
        .bind(&heartbeat.architecture)
        .bind(&heartbeat.core_state)
        .bind(heartbeat.memory_bytes as i64)
        .bind(heartbeat.disk_free_bytes as i64)
        .bind(heartbeat.cpu_percent)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn desired_generation_for_agent(
        &self,
        tenant_id: Uuid,
        agent_id: &str,
        node_id: Uuid,
    ) -> DatabaseResult<Option<i64>> {
        Ok(sqlx::query_scalar(
            "SELECT r.generation FROM nodes n
             JOIN config_revisions r ON r.tenant_id=n.tenant_id AND r.id=n.current_config_revision
             WHERE n.tenant_id=$1 AND n.id=$2 AND n.agent_id=$3
               AND r.publish_status='published' AND r.validation_status='validated'",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn desired_state_for_agent(
        &self,
        tenant_id: Uuid,
        agent_id: &str,
        node_id: Uuid,
    ) -> DatabaseResult<Option<DesiredConfigRecord>> {
        let row = sqlx::query(
            "SELECT r.id AS revision_id,r.node_id,r.generation,r.core_type,r.core_version,r.payload,r.content_hash,
                    COALESCE(applied.content_hash,'') AS expected_previous_hash
             FROM nodes n
             JOIN config_revisions r ON r.tenant_id=n.tenant_id AND r.id=n.current_config_revision
             LEFT JOIN config_revisions applied
               ON applied.tenant_id=n.tenant_id AND applied.id=n.applied_config_revision
             WHERE n.tenant_id=$1 AND n.id=$2 AND n.agent_id=$3
               AND r.publish_status='published' AND r.validation_status='validated'",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let payload: serde_json::Value = row.get("payload");
        Ok(Some(DesiredConfigRecord {
            revision_id: row.get("revision_id"),
            node_id: row.get("node_id"),
            generation: row.get("generation"),
            core_type: row.get("core_type"),
            core_version: row.get("core_version"),
            payload: serde_json::to_vec(&payload).unwrap_or_default(),
            content_hash: row.get("content_hash"),
            expected_previous_hash: row.get("expected_previous_hash"),
        }))
    }

    pub async fn record_agent_apply_result(
        &self,
        input: AgentApplyResultInput<'_>,
    ) -> DatabaseResult<bool> {
        let status = deployment_status_from_phase(input.phase);
        let message = truncate_chars(input.error_message, 512);
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("UPDATE config_deployments d SET status=$5,error_code=NULLIF($6,''),error_message=NULLIF($7,''),previous_hash=NULLIF($8,''),applied_hash=NULLIF($9,''),retry_count=$10,reported_at=now(),updated_at=now(),applied_generation=CASE WHEN $5='applied' THEN $4 ELSE d.applied_generation END FROM config_revisions r JOIN nodes n ON n.tenant_id=r.tenant_id AND n.id=r.node_id WHERE d.tenant_id=$1 AND d.node_id=$2 AND n.agent_id=$3 AND r.id=d.config_revision_id AND r.generation=$4 AND d.id=(SELECT d2.id FROM config_deployments d2 WHERE d2.tenant_id=d.tenant_id AND d2.node_id=d.node_id AND d2.config_revision_id=d.config_revision_id ORDER BY d2.created_at DESC,d2.id DESC LIMIT 1)")
            .bind(input.tenant_id).bind(input.node_id).bind(input.agent_id).bind(input.generation).bind(status).bind(input.error_code).bind(message).bind(input.previous_hash).bind(input.applied_hash).bind(input.retry_count).execute(&mut *tx).await?;
        if result.rows_affected() == 1 && status == "applied" {
            sqlx::query("UPDATE nodes SET applied_config_revision=r.id,applied_generation=$3,applied_at=now(),updated_at=now() FROM config_revisions r WHERE nodes.tenant_id=$1 AND nodes.id=$2 AND r.tenant_id=$1 AND r.node_id=$2 AND r.generation=$3")
                .bind(input.tenant_id).bind(input.node_id).bind(input.generation).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn ingest_agent_usage(&self, input: AgentUsageInput<'_>) -> DatabaseResult<bool> {
        let AgentUsageInput {
            tenant_id,
            agent_id,
            node_id,
            batch_id,
            sequence,
            window_start,
            window_end,
            payload,
        } = input;
        if batch_id.trim().is_empty() || window_end <= window_start {
            return Err(DatabaseError::InvalidUsagePayload(
                "batch_id and usage window are required".to_owned(),
            ));
        }
        let events = parse_usage_events(payload, window_start, window_end, agent_id, batch_id)?;
        let mut event_keys = std::collections::HashSet::with_capacity(events.len());
        for event in &events {
            if !event_keys.insert(event.event_key.as_str()) {
                return Err(DatabaseError::InvalidUsagePayload(
                    "event_key is duplicated within the batch".to_owned(),
                ));
            }
        }

        let mut transaction = self.pool.begin().await?;
        let receipt = sqlx::query(
            "INSERT INTO agent_usage_receipts
                (tenant_id,node_id,agent_id,batch_id,sequence,window_start,window_end,usage_payload)
             SELECT $1,$2,$3,$4,$5,to_timestamp($6),to_timestamp($7),$8
             WHERE EXISTS (SELECT 1 FROM nodes WHERE tenant_id=$1 AND id=$2 AND agent_id=$3)
             ON CONFLICT (tenant_id,agent_id,batch_id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(agent_id)
        .bind(batch_id)
        .bind(sequence)
        .bind(window_start)
        .bind(window_end)
        .bind(payload)
        .execute(&mut *transaction)
        .await?;
        if receipt.rows_affected() == 0 {
            transaction.commit().await?;
            return Ok(false);
        }

        for event in events {
            let inserted = sqlx::query(
                "INSERT INTO usage_events
                    (tenant_id,event_key,user_id,subscription_id,node_id,
                     window_start,window_end,download_bytes,upload_bytes,source_sequence)
                 SELECT $1,$2,s.user_id,s.id,$3,to_timestamp($4),to_timestamp($5),$6,$7,$8
                 FROM subscriptions s
                 JOIN subscription_nodes sn
                   ON sn.tenant_id=s.tenant_id AND sn.subscription_id=s.id
                  AND sn.node_id=$3
                 WHERE s.tenant_id=$1 AND s.id=$9 AND s.user_id=$10
                   AND s.status <> 'revoked'
                 ON CONFLICT (tenant_id,event_key) DO NOTHING",
            )
            .bind(tenant_id)
            .bind(&event.event_key)
            .bind(node_id)
            .bind(event.window_start)
            .bind(event.window_end)
            .bind(event.download_bytes)
            .bind(event.upload_bytes)
            .bind(sequence)
            .bind(event.subscription_id)
            .bind(event.user_id)
            .execute(&mut *transaction)
            .await?;
            if inserted.rows_affected() == 0 {
                let already_recorded: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM usage_events
                         WHERE tenant_id=$1 AND event_key=$2
                     )",
                )
                .bind(tenant_id)
                .bind(&event.event_key)
                .fetch_one(&mut *transaction)
                .await?;
                if !already_recorded {
                    return Err(DatabaseError::InvalidUsagePayload(
                        "subscription is not assigned to this node or user".to_owned(),
                    ));
                }
            }
        }
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn active_agent_release(
        &self,
        tenant_id: Uuid,
    ) -> DatabaseResult<Option<AgentReleaseRecord>> {
        let row = sqlx::query(
            "SELECT version,artifact_url,sha256,signature,signing_key_id,mandatory,
                    published_at::text AS published_at
             FROM agent_releases
             WHERE tenant_id=$1 AND revoked_at IS NULL
             ORDER BY published_at DESC
             LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AgentReleaseRecord::from_row))
    }

    pub async fn record_agent_upgrade_result(
        &self,
        input: AgentUpgradeResultInput<'_>,
    ) -> DatabaseResult<()> {
        let AgentUpgradeResultInput {
            tenant_id,
            node_id,
            agent_id,
            target_version,
            success,
            error_code,
            error_message,
        } = input;
        sqlx::query(
            "INSERT INTO agent_upgrade_results
                (tenant_id,node_id,agent_id,target_version,success,error_code,error_message)
             SELECT $1,$2,$3,$4,$5,$6,$7
             WHERE EXISTS (SELECT 1 FROM nodes WHERE tenant_id=$1 AND id=$2 AND agent_id=$3)",
        )
        .bind(tenant_id)
        .bind(node_id)
        .bind(agent_id)
        .bind(target_version)
        .bind(success)
        .bind(error_code)
        .bind(error_message)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UsageEventPayload {
    #[serde(alias = "event_key")]
    event_key: Option<String>,
    #[serde(alias = "user_id")]
    user_id: Uuid,
    #[serde(alias = "subscription_id")]
    subscription_id: Uuid,
    #[serde(default, alias = "window_start")]
    window_start: Option<i64>,
    #[serde(default, alias = "window_end")]
    window_end: Option<i64>,
    #[serde(alias = "download_bytes")]
    download_bytes: i64,
    #[serde(alias = "upload_bytes")]
    upload_bytes: i64,
}

#[derive(Debug)]
struct ParsedUsageEvent {
    event_key: String,
    user_id: Uuid,
    subscription_id: Uuid,
    window_start: i64,
    window_end: i64,
    download_bytes: i64,
    upload_bytes: i64,
}

fn parse_usage_events(
    payload: &serde_json::Value,
    default_window_start: i64,
    default_window_end: i64,
    agent_id: &str,
    batch_id: &str,
) -> DatabaseResult<Vec<ParsedUsageEvent>> {
    let raw_events: Vec<UsageEventPayload> = match payload.get("events") {
        Some(events) => serde_json::from_value(events.clone())
            .map_err(|error| DatabaseError::InvalidUsagePayload(format!("events: {error}")))?,
        None => vec![
            serde_json::from_value(payload.clone())
                .map_err(|error| DatabaseError::InvalidUsagePayload(format!("event: {error}")))?,
        ],
    };
    if raw_events.is_empty() {
        return Err(DatabaseError::InvalidUsagePayload(
            "at least one usage event is required".to_owned(),
        ));
    }
    raw_events
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let window_start = event.window_start.unwrap_or(default_window_start);
            let window_end = event.window_end.unwrap_or(default_window_end);
            if window_end <= window_start {
                return Err(DatabaseError::InvalidUsagePayload(
                    "usage window must end after it starts".to_owned(),
                ));
            }
            if event.download_bytes < 0 || event.upload_bytes < 0 {
                return Err(DatabaseError::InvalidUsagePayload(
                    "byte counters cannot be negative".to_owned(),
                ));
            }
            let event_key = event
                .event_key
                .filter(|key| !key.trim().is_empty())
                .unwrap_or_else(|| format!("{agent_id}:{batch_id}:{index}"));
            Ok(ParsedUsageEvent {
                event_key,
                user_id: event.user_id,
                subscription_id: event.subscription_id,
                window_start,
                window_end,
                download_bytes: event.download_bytes,
                upload_bytes: event.upload_bytes,
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct UserCredentials {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub status: String,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub active: bool,
}

#[derive(Clone, Debug)]
pub struct SessionSummaryRecord {
    pub id: Uuid,
    pub role: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub active: bool,
    pub current: bool,
}

impl SessionSummaryRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            role: row.get("role"),
            issued_at: row.get("issued_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.try_get("revoked_at").ok(),
            active: row.get("active"),
            current: row.get("current"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct DashboardStats {
    pub users: i64,
    pub active_subscriptions: i64,
    pub online_nodes: i64,
    pub traffic_bytes_24h: i64,
    pub failed_tasks: i64,
    pub generated_at: String,
}

#[derive(Clone, Debug)]
pub struct AuditLogRecord {
    pub id: Uuid,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub request_id: Option<String>,
    pub details: serde_json::Value,
    pub created_at: String,
    pub actor_user_id: Option<Uuid>,
    pub actor_email: Option<String>,
}

impl AuditLogRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            action: row.get("action"),
            resource_type: row.get("resource_type"),
            resource_id: row.try_get("resource_id").ok(),
            request_id: row.try_get("request_id").ok(),
            details: row.get("details"),
            created_at: row.get("created_at"),
            actor_user_id: row.try_get("actor_user_id").ok(),
            actor_email: row.try_get("actor_email").ok(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentReleaseRecord {
    pub version: String,
    pub artifact_url: String,
    pub sha256: String,
    pub signature: String,
    pub signing_key_id: String,
    pub mandatory: bool,
    pub published_at: String,
}

impl AgentReleaseRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            version: row.get("version"),
            artifact_url: row.get("artifact_url"),
            sha256: row.get("sha256"),
            signature: row.get("signature"),
            signing_key_id: row.get("signing_key_id"),
            mandatory: row.get("mandatory"),
            published_at: row.get("published_at"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentRegistrationRecord {
    pub node_id: Uuid,
    pub agent_id: String,
    pub agent_version: String,
    pub platform: String,
    pub architecture: String,
}

#[derive(Clone, Debug)]
pub struct AgentHeartbeatInput {
    pub agent_version: String,
    pub platform: String,
    pub architecture: String,
    pub core_state: String,
    pub memory_bytes: u64,
    pub disk_free_bytes: u64,
    pub cpu_percent: f64,
}

#[derive(Clone, Debug)]
pub struct DesiredConfigRecord {
    pub revision_id: Uuid,
    pub node_id: Uuid,
    pub generation: i64,
    pub core_type: String,
    pub core_version: String,
    pub payload: Vec<u8>,
    pub content_hash: String,
    pub expected_previous_hash: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UsageMaintenanceStats {
    pub buckets_upserted: u64,
    pub subscriptions_recalculated: u64,
    pub subscriptions_activated: u64,
    pub subscriptions_expired: u64,
}

#[derive(Clone, Debug)]
pub struct PlanInput {
    pub name: String,
    pub description: String,
    pub price_cents: i64,
    pub currency: String,
    pub duration_days: i32,
    pub quota_bytes: i64,
    pub device_limit: i32,
    pub status: String,
    pub node_group_ids: serde_json::Value,
}

#[derive(Clone, Debug, Default)]
pub struct PlanUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price_cents: Option<i64>,
    pub currency: Option<String>,
    pub duration_days: Option<i32>,
    pub quota_bytes: Option<i64>,
    pub device_limit: Option<i32>,
    pub status: Option<String>,
    pub node_group_ids: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct PlanRecord {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub price_cents: i64,
    pub currency: String,
    pub duration_days: i32,
    pub quota_bytes: i64,
    pub device_limit: i32,
    pub status: String,
    pub node_group_ids: serde_json::Value,
}

impl PlanRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            price_cents: row.get("price_cents"),
            currency: row.get("currency"),
            duration_days: row.get("duration_days"),
            quota_bytes: row.get("traffic_quota_bytes"),
            device_limit: row.get("device_limit"),
            status: row.get("status"),
            node_group_ids: row.get("node_group_ids"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NodeInput {
    pub name: String,
    pub region: String,
    pub address: String,
    pub port: i32,
    pub core: String,
    pub core_version: String,
    pub agent_version: String,
    pub tags: serde_json::Value,
}

#[derive(Clone, Debug, Default)]
pub struct NodeUpdate {
    pub name: Option<String>,
    pub region: Option<String>,
    pub address: Option<String>,
    pub port: Option<i32>,
    pub core: Option<String>,
    pub core_version: Option<String>,
    pub status: Option<String>,
    pub tags: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub struct NodeRecord {
    pub id: Uuid,
    pub name: String,
    pub region: String,
    pub address: String,
    pub status: String,
    pub core: String,
    pub core_version: String,
    pub agent_version: String,
    pub current_config_revision: Option<Uuid>,
    pub desired_generation: Option<i64>,
    pub applied_config_revision: Option<Uuid>,
    pub applied_generation: Option<i64>,
    pub applied_at: Option<String>,
    pub core_state: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub port: i32,
    pub tags: serde_json::Value,
}

impl NodeRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            region: row.get("region"),
            address: row.get("address"),
            status: row.get("status"),
            core: row.get("core_type"),
            core_version: row.get("core_version"),
            agent_version: row.get("agent_version"),
            current_config_revision: row.try_get("current_config_revision").ok(),
            desired_generation: row.try_get("desired_generation").ok().flatten(),
            applied_config_revision: row.try_get("applied_config_revision").ok().flatten(),
            applied_generation: row.try_get("applied_generation").ok().flatten(),
            applied_at: row.try_get("applied_at").ok().flatten(),
            core_state: row.try_get("agent_core_state").ok().flatten(),
            last_heartbeat_at: row.try_get("last_heartbeat_at").ok(),
            port: row.get("port"),
            tags: row.get("tags"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SubscriptionInput {
    pub user_id: Uuid,
    pub plan_id: Uuid,
    pub starts_at: Option<String>,
    pub expires_at: Option<String>,
    pub subscription_token: String,
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionUpdate {
    pub plan_id: Option<Uuid>,
    pub status: Option<String>,
    pub starts_at: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SubscriptionRecord {
    pub id: Uuid,
    pub user_email: String,
    pub plan: String,
    pub status: String,
    pub traffic_used_bytes: i64,
    pub traffic_quota_bytes: i64,
    pub expires_at: String,
    pub subscription_token: Option<String>,
    pub subscription_token_version: i64,
}

#[derive(Clone, Debug)]
pub struct OrderRecord {
    pub id: Uuid,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub created_at: String,
    pub paid_at: Option<String>,
    pub plan: String,
}

#[derive(Clone, Debug)]
pub struct AdminOrderRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub plan: String,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub created_at: String,
    pub paid_at: Option<String>,
}

impl AdminOrderRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            user_email: row.get("user_email"),
            plan: row.get("plan"),
            status: row.get("status"),
            amount_cents: row.get("amount_cents"),
            currency: row.get("currency"),
            created_at: row.get("created_at"),
            paid_at: row.try_get("paid_at").ok(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PaymentOrderRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub plan_id: Uuid,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub provider: String,
    pub provider_payment_id: Option<String>,
    pub paid_at: Option<String>,
}

impl PaymentOrderRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            plan_id: row.get("plan_id"),
            status: row.get("status"),
            amount_cents: row.get("amount_cents"),
            currency: row.get("currency"),
            provider: row.get("provider"),
            provider_payment_id: row.try_get("provider_payment_id").ok(),
            paid_at: row.try_get("paid_at").ok(),
        }
    }
}
impl OrderRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            status: row.get("status"),
            amount_cents: row.get("amount_cents"),
            currency: row.get("currency"),
            created_at: row.get("created_at"),
            paid_at: row.try_get("paid_at").ok(),
            plan: row.get("plan"),
        }
    }
}
#[derive(Clone, Debug)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub name: String,
    pub last_seen_at: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}
impl DeviceRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            last_seen_at: row.try_get("last_seen_at").ok(),
            created_at: row.get("created_at"),
            revoked_at: row.try_get("revoked_at").ok(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct UsageRecord {
    pub used_bytes: i64,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ConfigTemplateInput {
    pub name: String,
    pub description: String,
    pub core_type: String,
    pub core_version_range: String,
    pub status: String,
}
#[derive(Clone, Debug, Default)]
pub struct ConfigTemplateUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub core_type: Option<String>,
    pub core_version_range: Option<String>,
    pub status: Option<String>,
}
#[derive(Clone, Debug)]
pub struct ConfigTemplateRecord {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub core_type: String,
    pub core_version_range: String,
    pub status: String,
    pub updated_at: String,
    pub updated_by: String,
}
impl ConfigTemplateRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            core_type: row.get("core_type"),
            core_version_range: row.get("core_version_range"),
            status: row.get("status"),
            updated_at: row.get("updated_at"),
            updated_by: row.try_get("updated_by").unwrap_or_default(),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ConfigRevisionListInput<'a> {
    pub tenant_id: Uuid,
    pub node_id: Option<Uuid>,
    pub status: Option<&'a str>,
    pub search: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone, Debug)]
pub struct ConfigRevisionRecord {
    pub id: Uuid,
    pub template_id: String,
    pub node_id: Uuid,
    pub node_name: String,
    pub generation: i64,
    pub core_version: String,
    pub content_hash: String,
    pub signature_status: String,
    pub validation_status: String,
    pub publish_status: String,
    pub failure_reason: Option<String>,
    pub created_at: String,
    pub deployment_status: Option<String>,
    pub deployment_kind: Option<String>,
    pub deployment_error_code: Option<String>,
    pub deployment_error_message: Option<String>,
    pub deployment_updated_at: Option<String>,
    pub rollback_of: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub struct ConfigRevisionSigningRecord {
    pub node_id: Uuid,
    pub generation: i64,
    pub core_type: String,
    pub core_version: String,
    pub content_hash: String,
    pub payload: serde_json::Value,
}
impl ConfigRevisionRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            template_id: row.try_get("template_id").unwrap_or_default(),
            node_id: row.get("node_id"),
            node_name: row.try_get("node_name").unwrap_or_default(),
            generation: row.get("generation"),
            core_version: row.get("core_version"),
            content_hash: row.get("content_hash"),
            signature_status: row.try_get("signature_status").unwrap_or_default(),
            validation_status: row.get("validation_status"),
            publish_status: row.get("publish_status"),
            failure_reason: row.try_get("failure_reason").ok(),
            created_at: row.get("created_at"),
            deployment_status: row.try_get("deployment_status").ok().flatten(),
            deployment_kind: row.try_get("deployment_kind").ok().flatten(),
            deployment_error_code: row.try_get("deployment_error_code").ok().flatten(),
            deployment_error_message: row.try_get("deployment_error_message").ok().flatten(),
            deployment_updated_at: row.try_get("deployment_updated_at").ok().flatten(),
            rollback_of: row.try_get("rollback_of").ok().flatten(),
        }
    }
}

impl SubscriptionRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            user_email: row.try_get::<String, _>("user_email").unwrap_or_default(),
            plan: row.try_get::<String, _>("plan").unwrap_or_default(),
            status: row.get("status"),
            traffic_used_bytes: row.get("traffic_used_bytes"),
            traffic_quota_bytes: row.get("traffic_quota_bytes"),
            expires_at: row.get("expires_at"),
            subscription_token: row.try_get("subscription_token").ok(),
            subscription_token_version: row.try_get("subscription_token_version").unwrap_or(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CREATE_ORDER_IDEMPOTENT_SQL, CREATE_ORDER_SQL, DatabaseError, deployment_status_from_phase,
        parse_usage_events,
    };
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn apply_phases_map_to_deployment_statuses() {
        assert_eq!(deployment_status_from_phase("applied"), "applied");
        assert_eq!(deployment_status_from_phase("rolled_back"), "rolled_back");
        assert_eq!(deployment_status_from_phase("rejected"), "failed");
        assert_eq!(deployment_status_from_phase("unknown"), "failed");
    }

    #[test]
    fn order_creation_queries_only_select_active_plans() {
        for query in [CREATE_ORDER_SQL, CREATE_ORDER_IDEMPOTENT_SQL] {
            assert!(
                query.contains("AND status='active'"),
                "order creation must reject archived plans"
            );
        }
    }

    #[test]
    fn idempotency_parameter_conflicts_are_classified_as_conflicts() {
        assert!(DatabaseError::IdempotencyConflict.is_conflict());
        assert!(!DatabaseError::PlanUnavailable.is_conflict());
    }

    #[test]
    fn usage_payload_supports_single_and_batched_events() {
        let user_id = Uuid::from_u128(1);
        let subscription_id = Uuid::from_u128(2);
        let single = parse_usage_events(
            &json!({
                "userId": user_id,
                "subscriptionId": subscription_id,
                "downloadBytes": 12,
                "uploadBytes": 3
            }),
            100,
            200,
            "agent-1",
            "batch-1",
        )
        .unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].event_key, "agent-1:batch-1:0");
        let batched = parse_usage_events(
            &json!({"events": [{
                "event_key": "event-1",
                "user_id": user_id,
                "subscription_id": subscription_id,
                "download_bytes": 5,
                "upload_bytes": 1
            }]}),
            100,
            200,
            "agent-1",
            "batch-2",
        )
        .unwrap();
        assert_eq!(batched[0].event_key, "event-1");
        assert_eq!(batched[0].download_bytes, 5);
    }

    #[test]
    fn usage_payload_rejects_negative_counters() {
        let error = parse_usage_events(
            &json!({
                "userId": Uuid::from_u128(1),
                "subscriptionId": Uuid::from_u128(2),
                "downloadBytes": -1,
                "uploadBytes": 0
            }),
            100,
            200,
            "agent-1",
            "batch-1",
        )
        .unwrap_err();
        assert!(matches!(error, DatabaseError::InvalidUsagePayload(_)));
    }
}
