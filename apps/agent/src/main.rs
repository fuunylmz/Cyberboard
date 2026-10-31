use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cyberboard_agent_protocol::generated::{
    GetDesiredStateRequest, GetReleaseManifestRequest, HeartbeatRequest, RegisterAgentRequest,
    ReportApplyResultRequest, ReportUpgradeResultRequest,
};
use cyberboard_config::AgentConfig;
use cyberboard_config_compiler::SignedConfigEnvelope;
use cyberboard_config_compiler::hex_hash;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

mod control_plane;
mod identity;
mod runtime;
mod tonic_transport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cyberboard_observability::init("cyberboard_agent");
    let mut config = AgentConfig::from_env()?;
    let stored_identity = identity::AgentIdentity::load(&config.identity_path)?;
    if let Some(identity) = stored_identity.as_ref() {
        if config.ca_cert_path.is_none() {
            config.ca_cert_path = identity.ca_cert_path.clone();
        }
        if config.client_cert_path.is_none() {
            config.client_cert_path = identity.client_cert_path.clone();
        }
        if config.client_key_path.is_none() {
            config.client_key_path = identity.client_key_path.clone();
        }
    }
    if let (Some(configured), Some(stored)) = (config.node_id, stored_identity.as_ref()) {
        if configured != stored.node_id {
            return Err("CYBERBOARD_NODE_ID does not match persisted agent identity".into());
        }
    }
    let node_uuid = config
        .node_id
        .or_else(|| stored_identity.as_ref().map(|identity| identity.node_id))
        .ok_or("CYBERBOARD_NODE_ID or persisted agent identity is required")?;
    let node_id = node_uuid.to_string();
    let public_key = stored_identity
        .as_ref()
        .map(|identity| identity.public_key.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(agent_public_key);
    let mut persisted_agent_id = stored_identity
        .as_ref()
        .map(|identity| identity.agent_id.clone());
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
    let insecure_configured = config.insecure && config.control_plane_url.starts_with("http://");
    let mut transport = if tls_configured || insecure_configured {
        match tonic_transport::TonicAgentTransport::connect_with_backoff(&config, 5).await {
            Ok(mut value) => {
                let agent_id = if let Some(identity) = stored_identity.as_ref() {
                    info!(agent_id = %identity.agent_id, "reusing persisted agent identity");
                    Some(identity.agent_id.clone())
                } else {
                    let registration = RegisterAgentRequest {
                        one_time_registration_token: std::env::var(
                            "CYBERBOARD_AGENT_REGISTRATION_TOKEN",
                        )
                        .unwrap_or_default(),
                        agent_public_key: public_key.clone(),
                        agent_version: env!("CARGO_PKG_VERSION").into(),
                        platform: std::env::consts::OS.into(),
                        architecture: std::env::consts::ARCH.into(),
                        unix_time: unix_now(),
                        nonce: uuid::Uuid::new_v4().to_string(),
                    };
                    match value.register(registration).await {
                        Ok(agent_id) => {
                            persisted_agent_id = Some(agent_id.clone());
                            let saved = identity::AgentIdentity {
                                agent_id: agent_id.clone(),
                                node_id: node_uuid,
                                public_key: public_key.clone(),
                                ca_cert_path: config.ca_cert_path.clone(),
                                client_cert_path: config.client_cert_path.clone(),
                                client_key_path: config.client_key_path.clone(),
                            };
                            saved.persist(&config.identity_path)?;
                            info!(%agent_id, "agent registered and identity persisted");
                            Some(agent_id)
                        }
                        Err(error) => {
                            warn!(%error, "agent registration failed");
                            None
                        }
                    }
                };
                agent_id.map(|agent_id| (value, agent_id, public_key.clone()))
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
                if transport.is_none() {
                    if let Some(agent_id) = persisted_agent_id.clone() {
                        match tonic_transport::TonicAgentTransport::connect_with_backoff(&config, 1).await {
                            Ok(client) => {
                                info!(%agent_id, "agent transport reconnected");
                                transport = Some((client, agent_id, public_key.clone()));
                            }
                            Err(error) => warn!(%error, "agent reconnect failed"),
                        }
                    }
                }
                let mut heartbeat_failed = false;
                if let Some((client, agent_id, public_key)) = transport.as_mut() {
                    let now = unix_now();
                    let heartbeat = HeartbeatRequest { agent_id: agent_id.clone(), node_id: node_id.clone(), agent_version: env!("CARGO_PKG_VERSION").into(), core_versions: vec!["sing-box".into()], platform: std::env::consts::OS.into(), architecture: std::env::consts::ARCH.into(), current_config_revision: String::new(), core_state: "unknown".into(), memory_bytes: 0, disk_free_bytes: 0, cpu_percent: 0.0, unix_time: now, nonce: uuid::Uuid::new_v4().to_string(), agent_public_key: public_key.clone() };
                    heartbeat_failed = match client.heartbeat(heartbeat).await {
                        Ok(()) => false,
                        Err(error) => { warn!(%error, "control-plane heartbeat failed"); true }
                    };
                    if !heartbeat_failed {
                        let manifest = client.release_manifest(GetReleaseManifestRequest {
                            agent_id: agent_id.clone(),
                            node_id: node_id.clone(),
                            current_agent_version: env!("CARGO_PKG_VERSION").into(),
                            agent_public_key: public_key.clone(),
                        }).await;
                        if let Ok(manifest) = manifest {
                            if !manifest.version.is_empty() && manifest.version != env!("CARGO_PKG_VERSION") {
                                let validation = validate_release_manifest(&manifest);
                                if let Err(error) = &validation {
                                    warn!(target_version = %manifest.version, %error, "agent release manifest rejected");
                                } else {
                                    warn!(target_version = %manifest.version, "agent release manifest is available; automatic binary replacement is disabled");
                                }
                                let _ = client.report_upgrade(ReportUpgradeResultRequest {
                                    agent_id: agent_id.clone(),
                                    node_id: node_id.clone(),
                                    target_version: manifest.version,
                                    success: validation.is_ok(),
                                    error_code: if validation.is_ok() { "automatic_upgrade_disabled" } else { "invalid_release_manifest" }.into(),
                                    error_message: validation.err().unwrap_or_else(|| "release manifest verification/download policy is not configured".into()),
                                    agent_public_key: public_key.clone(),
                                }).await;
                            }
                        }
                        let desired = client.desired_state(GetDesiredStateRequest { agent_id: agent_id.clone(), node_id: node_id.clone(), current_generation: String::new(), current_content_hash: String::new(), last_applied_generation: 0, agent_public_key: public_key.clone() }).await;
                        if let Ok(response) = desired {
                            if !response.signed_config.is_empty() {
                                let result = apply_desired(&node_id, &response);
                                let (phase, code, hash, cas) = match result { Ok(hash) => ("applied", String::new(), hash, true), Err(error) => ("rejected", error, String::new(), false) };
                                let _ = client.report_apply(ReportApplyResultRequest { agent_id: agent_id.clone(), node_id: node_id.clone(), generation: response.generation, previous_hash: response.expected_previous_hash.clone(), applied_hash: hash, phase: phase.into(), error_code: code, error_message: String::new(), retry_count: 0, unix_time: now, expected_previous_hash: response.expected_previous_hash, compare_and_swap_ok: cas, agent_public_key: public_key.clone() }).await;
                            }
                        }
                    }
                }
                if heartbeat_failed {
                    transport = None;
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

fn agent_public_key() -> String {
    if let Ok(value) = std::env::var("CYBERBOARD_AGENT_PUBLIC_KEY") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    // Production deployments should persist and provision this key through the
    // node installer. The ephemeral fallback keeps local registration honest by
    // sending a real Ed25519 public key instead of an empty placeholder.
    let signing_key = SigningKey::generate(&mut OsRng);
    BASE64.encode(signing_key.verifying_key().to_bytes())
}

fn validate_release_manifest(
    manifest: &cyberboard_agent_protocol::generated::ReleaseManifestResponse,
) -> Result<(), String> {
    if manifest.artifact_url.trim().is_empty() {
        return Err("artifact_url is empty".to_owned());
    }
    if manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("sha256 must be a 64-character hexadecimal digest".to_owned());
    }
    if manifest.signature.trim().is_empty() || manifest.signing_key_id.trim().is_empty() {
        return Err("signature and signing_key_id are required".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod release_tests {
    use super::validate_release_manifest;
    use cyberboard_agent_protocol::generated::ReleaseManifestResponse;

    #[test]
    fn release_manifest_validation_rejects_missing_integrity_fields() {
        let manifest = ReleaseManifestResponse {
            version: "0.2.0".to_owned(),
            artifact_url: "https://example.invalid/agent".to_owned(),
            sha256: "bad".to_owned(),
            signature: String::new(),
            signing_key_id: String::new(),
            mandatory: false,
        };
        assert!(validate_release_manifest(&manifest).is_err());
    }
}

fn apply_desired(
    node_id: &str,
    response: &cyberboard_agent_protocol::generated::DesiredStateResponse,
) -> Result<String, String> {
    let envelope: SignedConfigEnvelope = serde_json::from_slice(&response.signed_config)
        .map_err(|_| "invalid_envelope".to_owned())?;
    let target = uuid::Uuid::parse_str(node_id).map_err(|_| "invalid_node_id".to_owned())?;
    if envelope.target_node != target
        || envelope.generation.to_string() != response.generation
        || (response.generation_number != 0 && response.generation_number != envelope.generation)
    {
        return Err("target_or_generation_mismatch".into());
    }
    let payload_hash = hex_hash(&envelope.payload);
    if (!response.content_hash.is_empty() && response.content_hash != payload_hash)
        || envelope.content_hash != payload_hash
    {
        return Err("content_hash_mismatch".into());
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
    let current = runtime
        .current_state()
        .map_err(|_| "runtime_state_unavailable".to_owned())?;
    if envelope.generation < current.generation {
        return Err("stale_generation".into());
    }
    if envelope.generation == current.generation {
        if current.content_hash == payload_hash {
            return Ok(payload_hash);
        }
        return Err("generation_hash_conflict".into());
    }
    if !response.expected_previous_hash.is_empty()
        && response.expected_previous_hash != current.content_hash
    {
        return Err("compare_and_swap_conflict".into());
    }
    runtime::ensure_parent(runtime.config_path())
        .map_err(|_| "runtime_parent_unavailable".to_owned())?;
    runtime
        .apply(&envelope.payload, envelope.generation, current.generation)
        .map_err(|_| String::from("runtime_apply_failed"))?;
    runtime
        .record_state(&runtime::AppliedState {
            generation: envelope.generation,
            content_hash: payload_hash.clone(),
        })
        .map_err(|_| "runtime_state_write_failed".to_owned())?;
    Ok(payload_hash)
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
