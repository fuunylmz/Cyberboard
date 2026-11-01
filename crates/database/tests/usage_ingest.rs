use cyberboard_database::{
    AgentUsageInput, Database, NodeInput, PlanInput, SubscriptionInput, UsageIngestOutcome,
};
use serde_json::json;
use uuid::Uuid;

async fn database() -> Option<Database> {
    let url = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let database = Database::connect(&url).await.expect("connect postgres");
    database.migrate().await.expect("apply migrations");
    Some(database)
}

async fn fixture(database: &Database) -> (Uuid, Uuid, Uuid, String) {
    let tenant_id = Uuid::new_v4();
    database.ensure_tenant(tenant_id).await.unwrap();
    let user = database
        .create_user(
            tenant_id,
            Uuid::nil(),
            &format!("usage-{}@example.com", Uuid::new_v4().simple()),
            "test-hash",
            "Usage User",
        )
        .await
        .unwrap();
    let plan = database
        .create_plan(
            tenant_id,
            Uuid::nil(),
            &PlanInput {
                name: format!("usage-plan-{}", Uuid::new_v4().simple()),
                description: String::new(),
                price_cents: 0,
                currency: "USD".into(),
                duration_days: 30,
                quota_bytes: 1_000_000,
                device_limit: 1,
                status: "active".into(),
                node_group_ids: json!([]),
            },
        )
        .await
        .unwrap();
    let node = database
        .create_node(
            tenant_id,
            Uuid::nil(),
            &NodeInput {
                name: format!("usage-node-{}", Uuid::new_v4().simple()),
                region: "test".into(),
                address: "127.0.0.1".into(),
                port: 18129,
                core: "sing-box".into(),
                core_version: "test".into(),
                agent_version: "test".into(),
                tags: json!([]),
            },
        )
        .await
        .unwrap();
    let agent_id = format!("usage-agent-{}", Uuid::new_v4().simple());
    sqlx::query("UPDATE nodes SET agent_id=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(node.id)
        .bind(&agent_id)
        .execute(database.pool())
        .await
        .unwrap();
    let subscription = database
        .create_subscription(
            tenant_id,
            Uuid::nil(),
            &SubscriptionInput {
                user_id: user.id,
                plan_id: plan.id,
                starts_at: Some("2020-01-01T00:00:00Z".into()),
                expires_at: Some("2099-01-01T00:00:00Z".into()),
                subscription_token: format!("usage-token-{}", Uuid::new_v4().simple()),
            },
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO subscription_nodes (tenant_id,subscription_id,node_id) VALUES ($1,$2,$3)",
    )
    .bind(tenant_id)
    .bind(subscription.id)
    .bind(node.id)
    .execute(database.pool())
    .await
    .unwrap();
    (tenant_id, user.id, node.id, agent_id)
}

fn payload(username: impl Into<String>, download: i64, upload: i64) -> serde_json::Value {
    json!({
        "version": 1,
        "counters": [{
            "username": username.into(),
            "download_bytes": download,
            "upload_bytes": upload
        }]
    })
}

#[allow(clippy::too_many_arguments)]
async fn ingest(
    database: &Database,
    tenant_id: Uuid,
    node_id: Uuid,
    agent_id: &str,
    batch_id: &str,
    value: &serde_json::Value,
    start: i64,
    end: i64,
) -> UsageIngestOutcome {
    database
        .ingest_agent_usage(AgentUsageInput {
            tenant_id,
            agent_id,
            node_id,
            batch_id,
            sequence: {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                batch_id.hash(&mut hasher);
                (hasher.finish() & i64::MAX as u64) as i64
            },
            window_start: start,
            window_end: end,
            payload: value,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn usage_ingest_is_idempotent_and_maintenance_rebuilds_totals() {
    let Some(database) = database().await else {
        eprintln!("skipped usage ingest tests: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let (tenant_id, user_id, node_id, agent_id) = fixture(&database).await;
    let start = 1_700_000_000;
    let end = start + 60;
    let value = payload(user_id.to_string(), 120, 30);

    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            &agent_id,
            "batch-idempotent",
            &value,
            start,
            end
        )
        .await,
        UsageIngestOutcome::Inserted
    );
    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            &agent_id,
            "batch-idempotent",
            &value,
            start,
            end
        )
        .await,
        UsageIngestOutcome::Duplicate
    );

    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM usage_events WHERE tenant_id=$1 AND node_id=$2 AND event_key=$3",
    )
    .bind(tenant_id)
    .bind(node_id)
    .bind(format!("batch-idempotent:{user_id}"))
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(event_count, 1);
    let used: i64 = sqlx::query_scalar(
        "SELECT s.traffic_used_bytes FROM subscriptions s JOIN subscription_nodes sn ON sn.tenant_id=s.tenant_id AND sn.subscription_id=s.id WHERE sn.tenant_id=$1 AND sn.node_id=$2",
    )
    .bind(tenant_id)
    .bind(node_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(used, 150);
    let bucket_totals_before: (i64, i64, i64) = sqlx::query_as(
        "SELECT download_bytes,upload_bytes,event_count FROM usage_buckets WHERE tenant_id=$1 AND user_id=$2",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(bucket_totals_before, (120, 30, 1));

    database.run_usage_maintenance(tenant_id).await.unwrap();
    let rebuilt_used: i64 = sqlx::query_scalar(
        "SELECT traffic_used_bytes FROM subscriptions WHERE tenant_id=$1 AND user_id=$2",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(rebuilt_used, 150);
    let bucket_totals: (i64, i64, i64) = sqlx::query_as(
        "SELECT download_bytes,upload_bytes,event_count FROM usage_buckets WHERE tenant_id=$1 AND user_id=$2",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(bucket_totals, (120, 30, 1));
}

#[tokio::test]
async fn usage_ingest_skips_unknown_users_and_rejects_wrong_agent_node() {
    let Some(database) = database().await else {
        eprintln!("skipped usage identity tests: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let (tenant_id, user_id, node_id, agent_id) = fixture(&database).await;
    let start = 1_700_010_000;
    let end = start + 60;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE tenant_id=$1")
        .bind(tenant_id)
        .fetch_one(database.pool())
        .await
        .unwrap();

    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            &agent_id,
            "batch-unknown",
            &payload(Uuid::new_v4().to_string(), 1, 1),
            start,
            end
        )
        .await,
        UsageIngestOutcome::Inserted
    );
    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            &agent_id,
            "batch-zero",
            &payload(user_id.to_string(), 0, 0),
            start,
            end,
        )
        .await,
        UsageIngestOutcome::Inserted
    );
    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            &agent_id,
            "batch-nonuuid",
            &payload("not-a-uuid", 2, 2),
            start,
            end,
        )
        .await,
        UsageIngestOutcome::Inserted
    );
    let other_node = database
        .create_node(
            tenant_id,
            Uuid::nil(),
            &NodeInput {
                name: format!("usage-unassigned-{}", Uuid::new_v4().simple()),
                region: "test".into(),
                address: "127.0.0.1".into(),
                port: 18128,
                core: "sing-box".into(),
                core_version: "test".into(),
                agent_version: "test".into(),
                tags: json!([]),
            },
        )
        .await
        .unwrap();
    let other_agent = format!("usage-agent-{}", Uuid::new_v4().simple());
    sqlx::query("UPDATE nodes SET agent_id=$3 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(other_node.id)
        .bind(&other_agent)
        .execute(database.pool())
        .await
        .unwrap();
    assert_eq!(
        ingest(
            &database,
            tenant_id,
            other_node.id,
            &other_agent,
            "batch-unassigned",
            &payload(user_id.to_string(), 3, 3),
            start,
            end,
        )
        .await,
        UsageIngestOutcome::Inserted
    );
    let node_event_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE tenant_id=$1 AND node_id=$2")
            .bind(tenant_id)
            .bind(other_node.id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(node_event_count, 0);
    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            "wrong-agent",
            "batch-wrong-agent",
            &payload(user_id.to_string(), 4, 4),
            start,
            end,
        )
        .await,
        UsageIngestOutcome::NodeMismatch
    );

    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE tenant_id=$1")
        .bind(tenant_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
    let used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(traffic_used_bytes),0)::bigint FROM subscriptions WHERE tenant_id=$1",
    )
    .bind(tenant_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(used, 0);
}

#[tokio::test]
async fn usage_event_window_can_be_ingested_after_subscription_expiry() {
    let Some(database) = database().await else {
        eprintln!("skipped usage window tests: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let (tenant_id, user_id, node_id, agent_id) = fixture(&database).await;
    let subscription_id: Uuid = sqlx::query_scalar(
        "SELECT s.id FROM subscriptions s WHERE s.tenant_id=$1 AND s.user_id=$2",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE subscriptions SET expires_at='2020-01-02T00:00:00Z' WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(subscription_id)
    .execute(database.pool())
    .await
    .unwrap();
    database.run_usage_maintenance(tenant_id).await.unwrap();
    let status: String =
        sqlx::query_scalar("SELECT status FROM subscriptions WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(subscription_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(status, "expired");
    let start = 1_577_836_800;
    let end = start + 60;
    assert_eq!(
        ingest(
            &database,
            tenant_id,
            node_id,
            &agent_id,
            "batch-expired-later",
            &payload(user_id.to_string(), 7, 8),
            start,
            end
        )
        .await,
        UsageIngestOutcome::Inserted
    );
    let used: i64 = sqlx::query_scalar(
        "SELECT traffic_used_bytes FROM subscriptions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(subscription_id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(used, 15);
}
