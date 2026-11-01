use cyberboard_database::{Database, PlanInput, SubscriptionInput, hash_session_token};
use uuid::Uuid;

async fn database() -> Option<Database> {
    let url = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let database = Database::connect(&url).await.expect("connect postgres");
    database.migrate().await.expect("apply migrations");
    Some(database)
}

#[tokio::test]
async fn proxy_credentials_are_idempotent_and_rotate_only_with_subscription_token() {
    let Some(database) = database().await else {
        eprintln!("skipped proxy credentials: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let tenant_id = Uuid::new_v4();
    database.ensure_tenant(tenant_id).await.unwrap();
    let actor_id = database
        .bootstrap_admin(
            tenant_id,
            &format!("admin-{}@example.com", Uuid::new_v4()),
            "hash",
        )
        .await
        .unwrap()
        .unwrap();
    let user = database
        .create_user(
            tenant_id,
            actor_id,
            &format!("user-{}@example.com", Uuid::new_v4()),
            "hash",
            "Proxy user",
        )
        .await
        .unwrap();
    let plan = database
        .create_plan(
            tenant_id,
            actor_id,
            &PlanInput {
                name: format!("plan-{}", Uuid::new_v4()),
                description: String::new(),
                price_cents: 0,
                currency: "USD".into(),
                duration_days: 30,
                quota_bytes: 1_000,
                device_limit: 1,
                status: "active".into(),
                node_group_ids: serde_json::json!([]),
            },
        )
        .await
        .unwrap();
    let subscription = database
        .create_subscription(
            tenant_id,
            actor_id,
            &SubscriptionInput {
                user_id: user.id,
                plan_id: plan.id,
                starts_at: None,
                expires_at: None,
                subscription_token: format!("cb_{}", Uuid::new_v4().simple()),
            },
        )
        .await
        .unwrap();
    let first = database
        .ensure_user_proxy_credentials(tenant_id, user.id)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        database.ensure_user_proxy_credentials(tenant_id, user.id),
        database.ensure_user_proxy_credentials(tenant_id, user.id),
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(first.password, left.password);
    assert_eq!(left.uuid, right.uuid);
    assert_eq!(
        first.shadowsocks_2022_key_128,
        right.shadowsocks_2022_key_128
    );
    assert_eq!(
        first.shadowsocks_2022_key_256,
        right.shadowsocks_2022_key_256
    );

    let next_token = format!("cb_{}", Uuid::new_v4().simple());
    database
        .rotate_subscription_token(
            tenant_id,
            user.id,
            &next_token,
            &hash_session_token(&next_token),
        )
        .await
        .unwrap()
        .expect("active subscription rotates");
    let rotated = database
        .ensure_user_proxy_credentials(tenant_id, user.id)
        .await
        .unwrap();
    assert_ne!(first.password, rotated.password);
    assert_ne!(first.uuid, rotated.uuid);
    assert_ne!(
        first.shadowsocks_2022_key_128,
        rotated.shadowsocks_2022_key_128
    );
    assert_ne!(
        first.shadowsocks_2022_key_256,
        rotated.shadowsocks_2022_key_256
    );
    let credential_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM user_proxy_credentials WHERE tenant_id=$1 AND user_id=$2",
    )
    .bind(tenant_id)
    .bind(user.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(credential_rows, 1);
    let _ = subscription;
}
