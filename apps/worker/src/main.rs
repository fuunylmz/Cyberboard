use std::time::Duration;

use cyberboard_config::WorkerConfig;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cyberboard_observability::init("cyberboard_worker");
    let config = WorkerConfig::from_env()?;
    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!(
        interval_secs = config.interval_secs,
        "Cyberboard worker started"
    );
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // The worker is intentionally a lifecycle placeholder. Durable
                // usage aggregation and outbox jobs land in the persistence slice.
                tracing::debug!("worker tick");
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
