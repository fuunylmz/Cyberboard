use cyberboard_database::{
    Database, NodeInput, NodeUpdate, PlanInput, PlanUpdate, SubscriptionInput, SubscriptionUpdate,
};
use serde_json::Value;
use uuid::Uuid;

type AuditRow = (String, String, Option<Uuid>, Option<Uuid>, Value);

#[tokio::test]
async fn admin_crud_writes_audit_atomically() {
    let Some(url) = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipped admin audit tests: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let database = Database::connect(&url).await.expect("connect postgres");
    database.migrate().await.expect("apply migrations");
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
            "User",
        )
        .await
        .unwrap();
    assert!(
        database
            .create_user(tenant_id, actor_id, &user.email, "hash", "Duplicate")
            .await
            .is_err()
    );
    let updated_user = database
        .update_user(
            tenant_id,
            actor_id,
            user.id,
            None,
            Some("Updated"),
            None,
            Some("new-hash"),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated_user.display_name, "Updated");
    assert!(
        !database
            .delete_user(tenant_id, actor_id, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert!(
        database
            .delete_user(tenant_id, actor_id, user.id)
            .await
            .unwrap()
    );

    let plan_input = |name: String| PlanInput {
        name,
        description: "test".into(),
        price_cents: 100,
        currency: "USD".into(),
        duration_days: 30,
        quota_bytes: 1024,
        device_limit: 1,
        status: "active".into(),
        node_group_ids: serde_json::json!([]),
    };
    let first_plan = database
        .create_plan(
            tenant_id,
            actor_id,
            &plan_input(format!("p1-{}", Uuid::new_v4())),
        )
        .await
        .unwrap();
    let second_plan = database
        .create_plan(
            tenant_id,
            actor_id,
            &plan_input(format!("p2-{}", Uuid::new_v4())),
        )
        .await
        .unwrap();
    database
        .update_plan(
            tenant_id,
            actor_id,
            first_plan.id,
            &PlanUpdate {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        !database
            .delete_plan(tenant_id, actor_id, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert!(
        database
            .delete_plan(tenant_id, actor_id, first_plan.id)
            .await
            .unwrap()
    );

    let node = database
        .create_node(
            tenant_id,
            actor_id,
            &NodeInput {
                name: format!("node-{}", Uuid::new_v4()),
                region: "test".into(),
                address: "127.0.0.1".into(),
                port: 443,
                core: "sing-box".into(),
                core_version: "1.0".into(),
                agent_version: "test".into(),
                tags: serde_json::json!([]),
            },
        )
        .await
        .unwrap();
    let changed_node = database
        .update_node(
            tenant_id,
            actor_id,
            node.id,
            &NodeUpdate {
                status: Some("maintenance".into()),
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(changed_node.status, "maintenance");
    assert!(
        !database
            .delete_node(tenant_id, actor_id, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert!(
        database
            .delete_node(tenant_id, actor_id, node.id)
            .await
            .unwrap()
    );

    let subscription = database
        .create_subscription(
            tenant_id,
            actor_id,
            &SubscriptionInput {
                user_id: updated_user.id,
                plan_id: second_plan.id,
                starts_at: None,
                expires_at: None,
                subscription_token: format!("test-{}", Uuid::new_v4()),
            },
        )
        .await
        .unwrap();
    database
        .update_subscription(
            tenant_id,
            actor_id,
            subscription.id,
            &SubscriptionUpdate {
                plan_id: Some(first_plan.id),
                status: Some("pending".into()),
                starts_at: None,
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(
        !database
            .delete_subscription(tenant_id, actor_id, Uuid::new_v4())
            .await
            .unwrap()
    );
    assert!(
        database
            .delete_subscription(tenant_id, actor_id, subscription.id)
            .await
            .unwrap()
    );

    let rows = sqlx::query("SELECT action,resource_type,resource_id,actor_user_id,details FROM audit_logs WHERE tenant_id=$1")
        .bind(tenant_id).fetch_all(database.pool()).await.unwrap();
    let logs: Vec<AuditRow> = rows
        .into_iter()
        .map(|row| {
            (
                sqlx::Row::get(&row, "action"),
                sqlx::Row::get(&row, "resource_type"),
                sqlx::Row::get(&row, "resource_id"),
                sqlx::Row::get(&row, "actor_user_id"),
                sqlx::Row::get(&row, "details"),
            )
        })
        .collect();
    let actions: Vec<&str> = logs.iter().map(|entry| entry.0.as_str()).collect();
    for action in [
        "user.create",
        "user.update",
        "user.password_reset",
        "user.delete",
        "plan.create",
        "plan.update",
        "plan.delete",
        "node.create",
        "node.update",
        "node.status_change",
        "node.delete",
        "subscription.create",
        "subscription.plan_change",
        "subscription.status_change",
        "subscription.delete",
    ] {
        assert!(actions.contains(&action), "missing audit action {action}");
    }
    for (action, resource_type, resource_id, actor, details) in &logs {
        assert_eq!(*actor, Some(actor_id));
        assert!(resource_id.is_some());
        assert_eq!(resource_type, action.split('.').next().unwrap());
        assert!(!details.to_string().contains("new-hash"));
    }
    let user_update = logs.iter().find(|entry| entry.0 == "user.update").unwrap();
    assert_eq!(user_update.4, serde_json::json!({"fields":["displayName"]}));
    let password_reset = logs
        .iter()
        .find(|entry| entry.0 == "user.password_reset")
        .unwrap();
    assert_eq!(password_reset.4, serde_json::json!({}));
    let status = logs
        .iter()
        .find(|entry| entry.0 == "node.status_change")
        .unwrap();
    assert_eq!(
        status.4,
        serde_json::json!({"from":"offline","to":"maintenance"})
    );
    let plan_change = logs
        .iter()
        .find(|entry| entry.0 == "subscription.plan_change")
        .unwrap();
    assert_eq!(
        plan_change.4,
        serde_json::json!({"fromPlanId":second_plan.id,"toPlanId":first_plan.id})
    );
    assert_eq!(logs.len(), 16);
}
