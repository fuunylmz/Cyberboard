use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{Database, DatabaseError, DatabaseResult};

const ADMIN_BOOTSTRAP_LOCK: i64 = 0x4359_4245_5242_4f41;

impl Database {
    pub async fn tenant_has_admin(&self, tenant_id: Uuid) -> DatabaseResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM user_roles ur
                JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
                WHERE ur.tenant_id=$1 AND r.name='admin'
            )",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(DatabaseError::from)
    }

    /// Creates the first tenant administrator. Existing administrators are never modified.
    pub async fn bootstrap_admin(
        &self,
        tenant_id: Uuid,
        email: &str,
        password_hash: &str,
    ) -> DatabaseResult<Option<Uuid>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ADMIN_BOOTSTRAP_LOCK)
            .execute(&mut *tx)
            .await?;

        let has_admin: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM user_roles ur
                JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
                WHERE ur.tenant_id=$1 AND r.name='admin'
            )",
        )
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await?;
        if has_admin {
            tx.commit().await?;
            return Ok(None);
        }

        let existing_user: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM users WHERE tenant_id=$1 AND lower(email)=lower($2)
            )",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(&mut *tx)
        .await?;
        if existing_user {
            return Err(DatabaseError::BootstrapAdminEmailConflict);
        }

        let role_id: Uuid = sqlx::query(
            "INSERT INTO roles (tenant_id,name,permissions)
             VALUES ($1,'admin',$2)
             ON CONFLICT (tenant_id,name) DO UPDATE SET permissions=EXCLUDED.permissions
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(json!(["*"]))
        .fetch_one(&mut *tx)
        .await?
        .get("id");

        let user_id: Uuid = sqlx::query(
            "INSERT INTO users (tenant_id,email,password_hash,display_name,status)
             VALUES ($1,$2,$3,$2,'active')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&mut *tx)
        .await?
        .get("id");

        sqlx::query("INSERT INTO user_roles (tenant_id,user_id,role_id) VALUES ($1,$2,$3)")
            .bind(tenant_id)
            .bind(user_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(Some(user_id))
    }
}
