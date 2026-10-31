//! PostgreSQL connection, migration, and repository boundary.
//!
//! Runtime SQL is used instead of `query!` macros so the workspace can compile
//! without a live database. Every repository method takes an explicit tenant ID
//! to keep tenant scoping visible at the call site.

use std::time::Duration;

use cyberboard_storage::{
    FIFTH_MIGRATION, FOURTH_MIGRATION, INITIAL_MIGRATION, SECOND_MIGRATION, SIXTH_MIGRATION,
    THIRD_MIGRATION,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

pub type DatabaseResult<T> = Result<T, DatabaseError>;

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
}

impl DatabaseError {
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Sqlx(error) if error.as_database_error().is_some_and(|db| db.code().as_deref() == Some("23505")))
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
            "SELECT id,name,region,address,status,core_type,core_version,agent_version,
                    current_config_revision,last_heartbeat_at::text AS last_heartbeat_at,port,tags
             FROM nodes WHERE tenant_id=$1 AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%' OR address ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR status=$3) ORDER BY created_at DESC,id LIMIT $4 OFFSET $5",
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
                       current_config_revision,last_heartbeat_at::text AS last_heartbeat_at,port,tags",
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
                       current_config_revision,last_heartbeat_at::text AS last_heartbeat_at,port,tags",
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
                    s.traffic_quota_bytes,s.expires_at::text AS expires_at,s.subscription_token
             FROM subscriptions s JOIN users u ON u.tenant_id=s.tenant_id AND u.id=s.user_id
             JOIN plans p ON p.tenant_id=s.tenant_id AND p.id=s.plan_id
             WHERE s.tenant_id=$1 AND ($2::text IS NULL OR u.email ILIKE '%' || $2 || '%' OR p.name ILIKE '%' || $2 || '%') AND ($3::text IS NULL OR s.status=$3) ORDER BY s.created_at DESC,s.id LIMIT $4 OFFSET $5",
        )
        .bind(tenant_id).bind(search).bind(status).bind(limit).bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(SubscriptionRecord::from_row).collect())
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

    async fn get_subscription(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> DatabaseResult<Option<SubscriptionRecord>> {
        let row = sqlx::query(
            "SELECT s.id,u.email AS user_email,p.name AS plan,s.status,s.traffic_used_bytes,
                    s.traffic_quota_bytes,s.expires_at::text AS expires_at,s.subscription_token
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
             WHERE tenant_id=$1 AND subscription_token=$2
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
        let rows = sqlx::query("SELECT n.id,n.name,n.region,n.address,n.status,n.core_type,n.core_version,n.agent_version,n.current_config_revision,last_heartbeat_at::text AS last_heartbeat_at,n.port,n.tags FROM nodes n JOIN subscription_nodes sn ON sn.tenant_id=n.tenant_id AND sn.node_id=n.id JOIN subscriptions s ON s.tenant_id=sn.tenant_id AND s.id=sn.subscription_id WHERE n.tenant_id=$1 AND s.subscription_token=$2 AND s.status='active' AND s.expires_at>now() ORDER BY n.created_at,n.id")
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
        let rows = sqlx::query("SELECT o.id,o.status,o.amount_cents,o.currency,o.created_at::text AS created_at,p.name AS plan FROM orders o JOIN plans p ON p.tenant_id=o.tenant_id AND p.id=o.plan_id WHERE o.tenant_id=$1 AND o.user_id=$2 ORDER BY o.created_at DESC,o.id LIMIT $3 OFFSET $4").bind(tenant_id).bind(user_id).bind(limit).bind(offset).fetch_all(&self.pool).await?;
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
    pub async fn count_devices(&self, tenant_id: Uuid, user_id: Uuid) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM devices WHERE tenant_id=$1 AND user_id=$2")
                .bind(tenant_id)
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?,
        )
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
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> DatabaseResult<Vec<ConfigRevisionRecord>> {
        let rows = sqlx::query("SELECT r.id,COALESCE(r.template_id::text,'') AS template_id,r.node_id,n.name AS node_name,r.generation,r.core_version,r.content_hash,CASE WHEN r.signature='' THEN 'pending' ELSE 'valid' END AS signature_status,r.validation_status,r.publish_status,r.failure_reason,r.created_at::text AS created_at FROM config_revisions r JOIN nodes n ON n.tenant_id=r.tenant_id AND n.id=r.node_id WHERE r.tenant_id=$1 ORDER BY r.created_at DESC,r.id LIMIT $2 OFFSET $3")
            .bind(tenant_id).bind(limit).bind(offset).fetch_all(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(ConfigRevisionRecord::from_row)
            .collect())
    }

    pub async fn create_config_revision(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        node_id: Uuid,
        generation: i64,
        core_version: &str,
        payload: &serde_json::Value,
        content_hash: &str,
    ) -> DatabaseResult<ConfigRevisionRecord> {
        let row = sqlx::query("INSERT INTO config_revisions (tenant_id,template_id,node_id,generation,core_type,core_version,content_hash,signature,validation_status,publish_status,payload) SELECT $1,$2,$3,$4,t.core_type,$5,$6,'','validated','draft',$7 FROM config_templates t WHERE t.tenant_id=$1 AND t.id=$2 RETURNING id,COALESCE(template_id::text,'') AS template_id,node_id,generation,core_version,content_hash,'pending' AS signature_status,validation_status,publish_status,failure_reason,created_at::text AS created_at")
            .bind(tenant_id).bind(template_id).bind(node_id).bind(generation).bind(core_version).bind(content_hash).bind(payload).fetch_one(&self.pool).await?;
        Ok(ConfigRevisionRecord::from_row(row))
    }

    pub async fn count_config_revisions(&self, tenant_id: Uuid) -> DatabaseResult<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM config_revisions WHERE tenant_id=$1")
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn set_config_publish_status(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_generation: i64,
        status: &str,
    ) -> DatabaseResult<Option<ConfigRevisionRecord>> {
        let row = sqlx::query("UPDATE config_revisions SET publish_status=$4, failure_reason=NULL WHERE tenant_id=$1 AND id=$2 AND generation=$3 AND validation_status='validated' RETURNING id,COALESCE(template_id::text,'') AS template_id,node_id,generation,core_version,content_hash,validation_status,publish_status,failure_reason,created_at::text AS created_at")
            .bind(tenant_id).bind(id).bind(expected_generation).bind(status).fetch_optional(&self.pool).await?;
        Ok(row.map(ConfigRevisionRecord::from_row))
    }
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
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: String,
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
}

#[derive(Clone, Debug)]
pub struct OrderRecord {
    pub id: Uuid,
    pub status: String,
    pub amount_cents: i64,
    pub currency: String,
    pub created_at: String,
    pub plan: String,
}
impl OrderRecord {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        Self {
            id: row.get("id"),
            status: row.get("status"),
            amount_cents: row.get("amount_cents"),
            currency: row.get("currency"),
            created_at: row.get("created_at"),
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
        }
    }
}
