use std::time::Duration;

use cyberboard_config::AgentConfig;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cyberboard_observability::init("cyberboard_agent");
    let config = AgentConfig::from_env()?;
    let node_id = config
        .node_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unregistered".to_owned());
    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    info!(
        control_plane = %config.control_plane_url,
        node_id = %node_id,
        protocol = cyberboard_agent_protocol::PROTOCOL_VERSION,
        "Cyberboard agent started"
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Transport and signed desired-state application are intentionally
                // placeholders until the mTLS gRPC implementation is added.
                tracing::debug!(node_id = %node_id, "agent heartbeat placeholder");
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
