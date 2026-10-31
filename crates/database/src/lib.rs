//! PostgreSQL connection, migration, and repository boundary.
//!
//! Runtime SQL is used instead of `query!` macros so the workspace can compile
//! without a live database. Every repository method takes an explicit tenant ID
//! to keep tenant scoping visible at the call site.

use std::time::Duration;

use cyberboard_storage::{INITIAL_MIGRATION, SECOND_MIGRATION};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use thiserror::Error;
use uuid::Uuid;

pub type DatabaseResult<T> = Result<T, DatabaseError>;

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
