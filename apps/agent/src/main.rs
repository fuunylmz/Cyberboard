use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cyberboard_agent_protocol::generated::{
    GetDesiredStateRequest, HeartbeatRequest, RegisterAgentRequest, ReportApplyResultRequest,
};
use cyberboard_config::AgentConfig;
use cyberboard_config_compiler::SignedConfigEnvelope;
use cyberboard_config_compiler::hex_hash;
use ed25519_dalek::VerifyingKey;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

mod control_plane;
mod runtime;
mod tonic_transport;

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

    let tls_configured = config.ca_cert_path.is_some()
        && config.client_cert_path.is_some()
        && config.client_key_path.is_some();
    let mut transport = if tls_configured {
        match tonic_transport::TonicAgentTransport::connect_with_backoff(&config, 5).await {
            Ok(mut value) => {
                let registration = RegisterAgentRequest {
                    one_time_registration_token: std::env::var(
                        "CYBERBOARD_AGENT_REGISTRATION_TOKEN",
                    )
                    .unwrap_or_default(),
                    agent_public_key: String::new(),
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                    platform: std::env::consts::OS.into(),
                    architecture: std::env::consts::ARCH.into(),
                    unix_time: 0,
                    nonce: String::new(),
                };
                match value.register(registration).await {
                    Ok(agent_id) => {
                        info!(%agent_id, "agent registered");
                        Some((value, agent_id))
                    }
                    Err(error) => {
                        warn!(%error, "agent registration failed");
                        None
                    }
                }
            }
            Err(error) => {
                warn!(%error, "control-plane connection failed; agent remains offline");
                None
            }
        }
    } else {
        info!("agent running in explicit local mode; mTLS transport is not configured");
        None
    };

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Some((client, agent_id)) = transport.as_mut() {
                    let now = unix_now();
                    let heartbeat = HeartbeatRequest { agent_id: agent_id.clone(), node_id: node_id.clone(), agent_version: env!("CARGO_PKG_VERSION").into(), core_versions: vec!["sing-box".into()], platform: std::env::consts::OS.into(), architecture: std::env::consts::ARCH.into(), current_config_revision: String::new(), core_state: "unknown".into(), memory_bytes: 0, disk_free_bytes: 0, cpu_percent: 0.0, unix_time: now, nonce: uuid::Uuid::new_v4().to_string() };
                    if let Err(error) = client.heartbeat(heartbeat).await { warn!(%error, "control-plane heartbeat failed"); }
                    let desired = client.desired_state(GetDesiredStateRequest { agent_id: agent_id.clone(), node_id: node_id.clone(), current_generation: String::new(), current_content_hash: String::new(), last_applied_generation: 0 }).await;
                    if let Ok(response) = desired {
                        if !response.signed_config.is_empty() {
                            let result = apply_desired(&node_id, &response);
                            let (phase, code, hash, cas) = match result { Ok(hash) => ("applied", String::new(), hash, true), Err(error) => ("rejected", error, String::new(), false) };
                            let _ = client.report_apply(ReportApplyResultRequest { agent_id: agent_id.clone(), node_id: node_id.clone(), generation: response.generation, previous_hash: response.expected_previous_hash.clone(), applied_hash: hash, phase: phase.into(), error_code: code, error_message: String::new(), retry_count: 0, unix_time: now, expected_previous_hash: response.expected_previous_hash, compare_and_swap_ok: cas }).await;
                        }
                    }
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

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn apply_desired(
    node_id: &str,
    response: &cyberboard_agent_protocol::generated::DesiredStateResponse,
) -> Result<String, String> {
    let envelope: SignedConfigEnvelope = serde_json::from_slice(&response.signed_config)
        .map_err(|_| "invalid_envelope".to_owned())?;
    let target = uuid::Uuid::parse_str(node_id).map_err(|_| "invalid_node_id".to_owned())?;
    if envelope.target_node != target || envelope.generation.to_string() != response.generation {
        return Err("target_or_generation_mismatch".into());
    }
    let key_bytes = BASE64
        .decode(
            std::env::var("CYBERBOARD_AGENT_TRUSTED_KEY")
                .map_err(|_| "missing_trusted_key".to_owned())?,
        )
        .map_err(|_| "invalid_trusted_key".to_owned())?;
    let key = VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| "invalid_trusted_key".to_owned())?,
    )
    .map_err(|_| "invalid_trusted_key".to_owned())?;
    envelope
        .verify(&key, chrono_now())
        .map_err(|_| "signature_or_expiry_invalid".to_owned())?;
    let path = std::env::var("CYBERBOARD_AGENT_CONFIG_PATH")
        .unwrap_or_else(|_| "/var/lib/cyberboard/sing-box.json".into());
    let binary = std::env::var("CYBERBOARD_SING_BOX_BINARY").unwrap_or_else(|_| "sing-box".into());
    let runtime = runtime::CoreRuntime::new(binary, path);
    runtime
        .apply(&envelope.payload, envelope.generation, envelope.generation)
        .map_err(|_| String::from("runtime_apply_failed"))?;
    Ok(hex_hash(&envelope.payload))
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
