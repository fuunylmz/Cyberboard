use cyberboard_database::Database;

#[tokio::test]
async fn postgres_schema_smoke_is_optional() {
    let Some(url) = std::env::var("CYBERBOARD_DATABASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
    else {
        eprintln!("skipped postgres smoke: CYBERBOARD_DATABASE_URL is not set");
        return;
    };
    let database = Database::connect(&url).await.expect("connect postgres");
    database
        .migrate()
        .await
        .expect("apply migrations 0001-0006");
    database.healthcheck().await.expect("database healthcheck");
    for table in [
        "config_templates",
        "config_revisions",
        "config_deployments",
        "subscription_nodes",
        "sessions",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(database.pool())
            .await
            .expect("check table");
        assert!(exists, "missing migrated table {table}");
    }
}
