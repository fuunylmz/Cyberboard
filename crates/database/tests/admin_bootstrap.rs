use cyberboard_database::{Database, DatabaseError};
use uuid::Uuid;

#[tokio::test]
async fn admin_bootstrap_is_transactional_and_idempotent() {
    let Some(url) = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipped admin bootstrap tests: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let database = Database::connect(&url).await.expect("connect postgres");
    database.migrate().await.expect("apply migrations");

    let tenant_id = Uuid::new_v4();
    database
        .ensure_tenant(tenant_id)
        .await
        .expect("create test tenant");
    let user_id = database
        .bootstrap_admin(tenant_id, "bootstrap@example.com", "test-argon2-hash")
        .await
        .expect("bootstrap first administrator")
        .expect("admin was created");
    assert_eq!(
        database
            .bootstrap_admin(tenant_id, "bootstrap@example.com", "replacement-hash")
            .await
            .expect("repeat bootstrap"),
        None
    );
    assert_eq!(
        database
            .bootstrap_admin(tenant_id, "different@example.com", "another-hash")
            .await
            .expect("bootstrap with different email after admin exists"),
        None
    );
    assert!(database.tenant_has_admin(tenant_id).await.unwrap());
    let user = database
        .find_user_credentials(tenant_id, "BOOTSTRAP@example.com")
        .await
        .unwrap()
        .expect("created user");
    assert_eq!(user.id, user_id);
    assert_eq!(user.password_hash, "test-argon2-hash");
    assert_eq!(user.status, "active");
    assert_eq!(user.roles, vec!["admin"]);
    let permissions: serde_json::Value =
        sqlx::query_scalar("SELECT permissions FROM roles WHERE tenant_id=$1 AND name='admin'")
            .bind(tenant_id)
            .fetch_one(database.pool())
            .await
            .expect("read admin role permissions");
    assert_eq!(permissions, serde_json::json!(["*"]));

    let conflict_tenant = Uuid::new_v4();
    database
        .ensure_tenant(conflict_tenant)
        .await
        .expect("create conflict tenant");
    database
        .create_user(
            conflict_tenant,
            "existing@example.com",
            "existing-hash",
            "Existing User",
        )
        .await
        .expect("create existing non-admin user");
    assert!(matches!(
        database
            .bootstrap_admin(conflict_tenant, "EXISTING@example.com", "bootstrap-hash")
            .await,
        Err(DatabaseError::BootstrapAdminEmailConflict)
    ));
    assert!(!database.tenant_has_admin(conflict_tenant).await.unwrap());

    let concurrent_tenant = Uuid::new_v4();
    database
        .ensure_tenant(concurrent_tenant)
        .await
        .expect("create concurrency tenant");
    let (first, second) = tokio::join!(
        database.bootstrap_admin(concurrent_tenant, "first@example.com", "first-hash"),
        database.bootstrap_admin(concurrent_tenant, "second@example.com", "second-hash"),
    );
    let first = first.expect("first concurrent bootstrap");
    let second = second.expect("second concurrent bootstrap");
    assert_eq!(
        usize::from(first.is_some()) + usize::from(second.is_some()),
        1
    );
    assert!(database.tenant_has_admin(concurrent_tenant).await.unwrap());
    let admin_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_roles ur
         JOIN roles r ON r.tenant_id=ur.tenant_id AND r.id=ur.role_id
         WHERE ur.tenant_id=$1 AND r.name='admin'",
    )
    .bind(concurrent_tenant)
    .fetch_one(database.pool())
    .await
    .expect("count concurrent administrators");
    assert_eq!(admin_count, 1);
}
