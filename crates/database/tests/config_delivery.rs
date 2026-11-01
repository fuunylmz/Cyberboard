use cyberboard_database::{
    AgentApplyResultInput, ConfigPublishInput, ConfigRevisionCreateInput, ConfigRevisionListInput,
    ConfigRollbackInput, ConfigTemplateInput, Database, NodeInput, PlanInput, SubscriptionInput,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn content_hash(value: &serde_json::Value) -> String {
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

#[tokio::test]
async fn config_deployment_lifecycle_is_honest_and_rolls_forward() {
    let Some(database) = database().await else {
        eprintln!("skipped config delivery: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let tenant_id = Uuid::new_v4();
    database.ensure_tenant(tenant_id).await.unwrap();
    let node = database
        .create_node(
            tenant_id,
            Uuid::nil(),
            &NodeInput {
                name: format!("delivery-{}", Uuid::new_v4().simple()),
                region: "test".into(),
                address: "127.0.0.1".into(),
                port: 443,
                core: "sing-box".into(),
                core_version: "1.0".into(),
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
                name: format!("template-{}", Uuid::new_v4().simple()),
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

    let payload_one = json!({"inbounds":[{"tag":"one"}]});
    let hash_one = content_hash(&payload_one);
    let revision_one = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 1,
            core_version: "1.0",
            payload: &payload_one,
            content_hash: &hash_one,
        })
        .await
        .unwrap()
        .unwrap();
    let _published_one = database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: revision_one.id,
            expected_generation: 1,
            expected_previous_hash: None,
            sign: &|_, _, _| "publish-artifact".to_owned(),
            actor_user_id: Uuid::nil(),
        })
        .await
        .unwrap()
        .unwrap();
    let published_hash_one: String = sqlx::query_scalar(
        "SELECT content_hash FROM config_revisions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(revision_one.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    let deployment: String = sqlx::query_scalar(
        "SELECT status FROM config_deployments WHERE tenant_id=$1 AND config_revision_id=$2",
    )
    .bind(tenant_id)
    .bind(revision_one.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(deployment, "pending");
    let audit_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='config.publish' AND resource_id=$2")
        .bind(tenant_id).bind(revision_one.id).fetch_one(database.pool()).await.unwrap();
    assert_eq!(audit_count, 1);

    assert!(
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
                applied_hash: &published_hash_one,
                retry_count: 0,
            })
            .await
            .unwrap()
    );
    let applied_generation: i64 =
        sqlx::query_scalar("SELECT applied_generation FROM nodes WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(node.id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert_eq!(applied_generation, 1);

    let listed_node = database
        .list_nodes(tenant_id, 20, 0, None, None)
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.id == node.id)
        .unwrap();
    assert_eq!(listed_node.current_config_revision, Some(revision_one.id));
    assert_eq!(listed_node.desired_generation, Some(1));
    assert_eq!(listed_node.applied_config_revision, Some(revision_one.id));
    assert_eq!(listed_node.applied_generation, Some(1));
    assert!(listed_node.applied_at.is_some());

    let search = node.name[..8].to_ascii_uppercase();
    let filtered = ConfigRevisionListInput {
        tenant_id,
        node_id: Some(node.id),
        status: Some("published"),
        search: Some(&search),
        limit: 20,
        offset: 0,
    };
    let filtered_revisions = database.list_config_revisions(filtered).await.unwrap();
    let filtered_count = database.count_config_revisions(filtered).await.unwrap();
    assert!(
        filtered_revisions
            .iter()
            .any(|revision| revision.id == revision_one.id)
    );
    assert_eq!(filtered_count, filtered_revisions.len() as i64);

    let payload_two = json!({"inbounds":[{"tag":"two"}]});
    let hash_two = content_hash(&payload_two);
    let revision_two = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 2,
            core_version: "1.0",
            payload: &payload_two,
            content_hash: &hash_two,
        })
        .await
        .unwrap()
        .unwrap();
    database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: revision_two.id,
            expected_generation: 2,
            expected_previous_hash: Some(&published_hash_one),
            sign: &|_, _, _| "publish-artifact".to_owned(),
            actor_user_id: Uuid::nil(),
        })
        .await
        .unwrap();
    let published_hash_two: String = sqlx::query_scalar(
        "SELECT content_hash FROM config_revisions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(revision_two.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(
        database
            .record_agent_apply_result(AgentApplyResultInput {
                tenant_id,
                agent_id: &agent_id,
                node_id: node.id,
                generation: 2,
                phase: "applied",
                error_code: "",
                error_message: "",
                previous_hash: &published_hash_one,
                applied_hash: &published_hash_two,
                retry_count: 0
            })
            .await
            .unwrap()
    );

    // A persisted gen1 report can arrive after gen2 is already applied. The
    // report remains accepted and its deployment receipt is updated, while
    // the node's applied state stays at the newer generation.
    assert!(
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
                applied_hash: &published_hash_one,
                retry_count: 0
            })
            .await
            .unwrap()
    );
    let (applied_revision, applied_generation): (Uuid, i64) = sqlx::query_as(
        "SELECT applied_config_revision, applied_generation FROM nodes WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(node.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(applied_revision, revision_two.id);
    assert_eq!(applied_generation, 2);
    let gen_one_deployment: String = sqlx::query_scalar(
        "SELECT status FROM config_deployments WHERE tenant_id=$1 AND config_revision_id=$2",
    )
    .bind(tenant_id)
    .bind(revision_one.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(gen_one_deployment, "applied");
    let gen_two_deployment: String = sqlx::query_scalar(
        "SELECT status FROM config_deployments WHERE tenant_id=$1 AND config_revision_id=$2",
    )
    .bind(tenant_id)
    .bind(revision_two.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(gen_two_deployment, "applied");

    let payload_draft = json!({"inbounds":[{"tag":"draft-three"}]});
    let draft_three = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 3,
            core_version: "1.0",
            payload: &payload_draft,
            content_hash: &content_hash(&payload_draft),
        })
        .await
        .unwrap()
        .unwrap();
    let rollback = database
        .rollback_config_revision(ConfigRollbackInput {
            tenant_id,
            revision_id: revision_two.id,
            expected_generation: 2,
            actor_user_id: Uuid::nil(),
            reason: Some("test rollback"),
            sign: &|node_id, generation, payload| {
                format!(
                    "signed:{node_id}:{generation}:{}",
                    content_hash(&serde_json::from_slice(&payload).unwrap())
                )
            },
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rollback.generation, 4);
    assert_eq!(rollback.rollback_of, Some(revision_one.id));
    assert_eq!(rollback.content_hash, published_hash_one);
    let old_status: String = sqlx::query_scalar(
        "SELECT publish_status FROM config_revisions WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant_id)
    .bind(revision_two.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(old_status, "rolled_back");
    let rollback_deployment: String = sqlx::query_scalar(
        "SELECT status FROM config_deployments WHERE tenant_id=$1 AND config_revision_id=$2",
    )
    .bind(tenant_id)
    .bind(rollback.id)
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(rollback_deployment, "pending");
    let rollback_audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE tenant_id=$1 AND action='config.rollback' AND resource_id=$2").bind(tenant_id).bind(rollback.id).fetch_one(database.pool()).await.unwrap();
    assert_eq!(rollback_audit, 1);
    let desired = database
        .desired_state_for_agent(tenant_id, &agent_id, node.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(desired.generation, 4);
    assert_eq!(desired.content_hash, published_hash_one);
    assert_eq!(desired.expected_previous_hash, published_hash_two);
    let stale_error = database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: draft_three.id,
            expected_generation: 3,
            expected_previous_hash: Some(&published_hash_one),
            sign: &|_, _, _| "publish-artifact".to_owned(),
            actor_user_id: Uuid::nil(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        stale_error,
        cyberboard_database::DatabaseError::ConfigConflict("stale_generation")
    ));
}

#[tokio::test]
async fn concurrent_migrations_are_serialized() {
    let Some(url) = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipped migration concurrency: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let first = Database::connect(&url).await.unwrap();
    let second = Database::connect(&url).await.unwrap();
    let (left, right) = tokio::join!(first.migrate(), second.migrate());
    left.unwrap();
    right.unwrap();
}

#[tokio::test]
async fn subscription_node_configs_return_active_applied_payload_and_credentials() {
    let Some(database) = database().await else {
        eprintln!("skipped subscription node configs: CYBERBOARD_DATABASE_URL is not set");
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
            &format!("subscriber-{}@example.com", Uuid::new_v4()),
            "hash",
            "Subscriber",
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
                node_group_ids: json!([]),
            },
        )
        .await
        .unwrap();
    let token = format!("cb_{}", Uuid::new_v4().simple());
    let subscription = database
        .create_subscription(
            tenant_id,
            actor_id,
            &SubscriptionInput {
                user_id: user.id,
                plan_id: plan.id,
                starts_at: None,
                expires_at: None,
                subscription_token: token.clone(),
            },
        )
        .await
        .unwrap();
    let credentials = database
        .ensure_user_proxy_credentials(tenant_id, user.id)
        .await
        .unwrap();
    let node = database
        .create_node(
            tenant_id,
            actor_id,
            &NodeInput {
                name: format!("subscription-node-{}", Uuid::new_v4().simple()),
                region: "test".into(),
                address: "127.0.0.1".into(),
                port: 443,
                core: "sing-box".into(),
                core_version: "1.0".into(),
                agent_version: "test".into(),
                tags: json!([]),
            },
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO subscription_nodes(tenant_id,subscription_id,node_id) VALUES($1,$2,$3)",
    )
    .bind(tenant_id)
    .bind(subscription.id)
    .bind(node.id)
    .execute(database.pool())
    .await
    .unwrap();
    let template = database
        .create_config_template(
            tenant_id,
            &ConfigTemplateInput {
                name: format!("template-{}", Uuid::new_v4().simple()),
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
    let payload = json!({
        "inbounds": [{"type": "vless", "tag": "subscription", "users": []}],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    });
    let revision = database
        .create_config_revision(ConfigRevisionCreateInput {
            tenant_id,
            template_id: template.id,
            node_id: node.id,
            generation: 1,
            core_version: "1.0",
            content_hash: &content_hash(&payload),
            payload: &payload,
        })
        .await
        .unwrap()
        .unwrap();
    database
        .publish_config_revision(ConfigPublishInput {
            tenant_id,
            revision_id: revision.id,
            expected_generation: 1,
            expected_previous_hash: None,
            sign: &|_, _, _| "publish-artifact".to_owned(),
            actor_user_id: actor_id,
        })
        .await
        .unwrap();
    let applied_payload: serde_json::Value =
        sqlx::query_scalar("SELECT payload FROM config_revisions WHERE tenant_id=$1 AND id=$2")
            .bind(tenant_id)
            .bind(revision.id)
            .fetch_one(database.pool())
            .await
            .unwrap();
    assert!(
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
                applied_hash: &content_hash(&applied_payload),
                retry_count: 0,
            })
            .await
            .unwrap()
    );

    let records = database
        .subscription_node_configs_for_token(tenant_id, &token)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.user_id, user.id);
    assert_eq!(record.node.id, node.id);
    assert_eq!(record.payload.as_ref(), Some(&applied_payload));
    assert_eq!(record.credentials.password, credentials.password);
    assert_eq!(record.credentials.uuid, credentials.uuid);
    assert_eq!(
        record.credentials.shadowsocks_2022_key_128,
        credentials.shadowsocks_2022_key_128
    );
    assert_eq!(
        record.credentials.shadowsocks_2022_key_256,
        credentials.shadowsocks_2022_key_256
    );

    database
        .delete_subscription(tenant_id, actor_id, subscription.id)
        .await
        .unwrap();
    assert!(
        database
            .subscription_node_configs_for_token(tenant_id, &token)
            .await
            .unwrap()
            .is_empty()
    );
}
