use cyberboard_database::{
    AgentApplyResultInput, ConfigPublishInput, ConfigRevisionCreateInput, ConfigRollbackInput,
    ConfigTemplateInput, Database, NodeInput, SubscriptionInput,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn hash(value: &serde_json::Value) -> String {
    Sha256::digest(serde_json::to_vec(value).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn database() -> Option<Database> {
    let url = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())?;
    let database = Database::connect(&url).await.expect("connect postgres");
    database.migrate().await.expect("apply migrations");
    Some(database)
}

fn payload(tag: &str) -> serde_json::Value {
    json!({
        "inbounds": [{
            "type": "vless",
            "tag": tag,
            "listen": "0.0.0.0",
            "listen_port": 443,
            "users": []
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
        "experimental": {
            "v2ray_api": {
                "listen": "127.0.0.1:10085",
                "stats": {"enabled": true, "users": []}
            }
        }
    })
}

#[tokio::test]
async fn rollback_rebuilds_users_from_current_assignments() {
    let Some(database) = database().await else {
        eprintln!("skipped rollback credentials: CYBERBOARD_DATABASE_URL is not set");
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
    let user_one = database
        .create_user(
            tenant_id,
            actor_id,
            &format!("one-{}@example.com", Uuid::new_v4()),
            "hash",
            "One",
        )
        .await
        .unwrap();
    let user_two = database
        .create_user(
            tenant_id,
            actor_id,
            &format!("two-{}@example.com", Uuid::new_v4()),
            "hash",
            "Two",
        )
        .await
        .unwrap();
    let plan = database
        .create_plan(
            tenant_id,
            actor_id,
            &cyberboard_database::PlanInput {
                name: format!("plan-{}", Uuid::new_v4()),
                description: String::new(),
                price_cents: 0,
                currency: "USD".into(),
                duration_days: 30,
                quota_bytes: 1_000,
                device_limit: 1,
                status: "active".into(),
                node_group_ids: json!([]),
            },
        )
        .await
        .unwrap();
    let subscription_one = database
        .create_subscription(
            tenant_id,
            actor_id,
            &SubscriptionInput {
                user_id: user_one.id,
                plan_id: plan.id,
                starts_at: None,
                expires_at: None,
                subscription_token: format!("cb_{}", Uuid::new_v4().simple()),
            },
        )
        .await
        .unwrap();
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
                core_version: "1.14.4".into(),
                agent_version: "test".into(),
                tags: json!([]),
            },
        )
        .await
        .unwrap();
    let template = database
        .create_config_template(
            tenant_id,
            &ConfigTemplateInput {
                name: format!("template-{}", Uuid::new_v4()),
                description: String::new(),
                core_type: "sing-box".into(),
                core_version_range: "*".into(),
                status: "active".into(),
            },
        )
        .await
        .unwrap();
    let agent_id = format!("agent-{}", Uuid::new_v4().simple());
    sqlx::query("UPDATE nodes SET agent_id=$3,agent_public_key=$4 WHERE tenant_id=$1 AND id=$2")
        .bind(tenant_id)
        .bind(node.id)
        .bind(&agent_id)
        .bind("test-public-key")
        .execute(database.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO subscription_nodes(tenant_id,subscription_id,node_id) VALUES($1,$2,$3)",
    )
    .bind(tenant_id)
    .bind(subscription_one.id)
    .bind(node.id)
    .execute(database.pool())
    .await
    .unwrap();

    let first_payload = payload("first");
    let first_revision = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 1,
            core_version: "1.14.4",
            content_hash: &hash(&first_payload),
            payload: &first_payload,
        })
        .await
        .unwrap()
        .unwrap();
    database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: first_revision.id,
            expected_generation: 1,
            expected_previous_hash: None,
            sign: &|_, _, _| "signed".into(),
            actor_user_id: actor_id,
        })
        .await
        .unwrap();
    database
        .record_agent_apply_result(AgentApplyResultInput {
            tenant_id,
            agent_id: &agent_id,
            node_id: node.id,
            generation: 1,
            phase: "applied",
            error_code: "",
            error_message: "",
            previous_hash: "",
            applied_hash: &hash(&payload("first")),
            retry_count: 0,
        })
        .await
        .unwrap();

    let second_payload = payload("second");
    let second_revision = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 2,
            core_version: "1.14.4",
            content_hash: &hash(&second_payload),
            payload: &second_payload,
        })
        .await
        .unwrap()
        .unwrap();
    database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: second_revision.id,
            expected_generation: 2,
            expected_previous_hash: None,
            sign: &|_, _, _| "signed".into(),
            actor_user_id: actor_id,
        })
        .await
        .unwrap();
    database
        .record_agent_apply_result(AgentApplyResultInput {
            tenant_id,
            agent_id: &agent_id,
            node_id: node.id,
            generation: 2,
            phase: "rolled_back",
            error_code: "health_check_failed",
            error_message: "restored previous",
            previous_hash: "",
            applied_hash: &hash(&payload("first")),
            retry_count: 1,
        })
        .await
        .unwrap();
    database
        .delete_subscription(tenant_id, actor_id, subscription_one.id)
        .await
        .unwrap();
    let subscription_two = database
        .create_subscription(
            tenant_id,
            actor_id,
            &SubscriptionInput {
                user_id: user_two.id,
                plan_id: plan.id,
                starts_at: None,
                expires_at: None,
                subscription_token: format!("cb_{}", Uuid::new_v4().simple()),
            },
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO subscription_nodes(tenant_id,subscription_id,node_id) VALUES($1,$2,$3)",
    )
    .bind(tenant_id)
    .bind(subscription_two.id)
    .bind(node.id)
    .execute(database.pool())
    .await
    .unwrap();

    let rollback = database
        .rollback_config_revision(ConfigRollbackInput {
            tenant_id,
            revision_id: second_revision.id,
            expected_generation: 2,
            actor_user_id: actor_id,
            reason: Some("credential test"),
            sign: &|_, _, _| "signed".into(),
        })
        .await
        .unwrap()
        .unwrap();
    let rolled_payload = database
        .config_revision_for_signing(tenant_id, rollback.id)
        .await
        .unwrap()
        .unwrap()
        .payload;
    let users = rolled_payload["inbounds"][0]["users"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["name"], user_two.id.to_string());
    assert_eq!(
        rolled_payload["experimental"]["v2ray_api"]["stats"]["users"][0],
        user_two.id.to_string()
    );
    assert_ne!(users[0]["name"], user_one.id.to_string());

    database
        .delete_subscription(tenant_id, actor_id, subscription_two.id)
        .await
        .unwrap();
    let empty_payload = payload("empty");
    let empty_revision = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 5,
            core_version: "1.14.4",
            content_hash: &hash(&empty_payload),
            payload: &empty_payload,
        })
        .await
        .unwrap()
        .unwrap();
    database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: empty_revision.id,
            expected_generation: 5,
            expected_previous_hash: None,
            sign: &|_, _, _| "signed".into(),
            actor_user_id: actor_id,
        })
        .await
        .unwrap();
    let published_empty = database
        .config_revision_for_signing(tenant_id, empty_revision.id)
        .await
        .unwrap()
        .unwrap()
        .payload;
    assert!(published_empty["inbounds"].as_array().unwrap().is_empty());
}
