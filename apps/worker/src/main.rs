use std::time::Duration;

use cyberboard_config::WorkerConfig;
use cyberboard_database::Database;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

mod maintenance;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cyberboard_observability::init("cyberboard_worker");
    let config = WorkerConfig::from_env()?;
    let database = if let Some(database_url) = config.database_url.as_deref() {
        let database = Database::connect(database_url).await?;
        database.migrate().await?;
        database.ensure_tenant(config.tenant_id).await?;
        info!(tenant_id = %config.tenant_id, "worker database initialized");
        Some(database)
    } else {
        warn!("CYBERBOARD_DATABASE_URL is not configured; usage maintenance is disabled");
        None
    };
    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!(
        interval_secs = config.interval_secs,
        "Cyberboard worker started"
    );
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Some(database) = database.as_ref() {
                    match maintenance::run_once(database, config.tenant_id).await {
                        Ok(stats) => info!(
                            buckets_upserted = stats.buckets_upserted,
                            subscriptions_recalculated = stats.subscriptions_recalculated,
                            subscriptions_activated = stats.subscriptions_activated,
                            subscriptions_expired = stats.subscriptions_expired,
                            "worker maintenance pass completed"
                        ),
                        Err(error) => warn!(%error, "worker maintenance pass failed; retrying on next tick"),
                    }
                } else {
                    tracing::debug!("worker tick skipped because database is disabled");
                }
            }
            signal = tokio::signal::ctrl_c() => {
                match signal {
                    Ok(()) => info!("shutdown signal received"),
                    Err(error) => warn!(%error, "shutdown signal unavailable"),
                }
                break;
            }
        }
    }

    Ok(())
}
