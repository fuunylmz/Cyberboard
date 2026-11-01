use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cyberboard_agent_protocol::generated::{
    DesiredStateResponse, GetDesiredStateRequest, GetReleaseManifestRequest, HeartbeatRequest,
    HeartbeatResponse, RegisterAgentRequest, ReportApplyResultRequest, ReportUpgradeResultRequest,
};
use cyberboard_config::AgentConfig;
use cyberboard_config_compiler::{SignedConfigEnvelope, hex_hash};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

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
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(agent_public_key);
    let mut agent_id = stored_identity
        .as_ref()
        .map(|identity| identity.agent_id.clone());
    let transport_configured = (config.ca_cert_path.is_some()
        && config.client_cert_path.is_some()
        && config.client_key_path.is_some())
        || (config.insecure && config.control_plane_url.starts_with("http://"));
    let trusted_key = match config.trusted_key.as_deref() {
        Some(encoded) => Some(parse_trusted_key(encoded)?),
        None if transport_configured => return Err(
            "CYBERBOARD_AGENT_TRUSTED_KEY is required when control-plane transport is configured"
                .into(),
        ),
        None => None,
    };
    let mut core = runtime::CoreSupervisor::new(
        &config.core_binary,
        &config.core_config_path,
        Duration::from_millis(config.health_grace_ms),
    )
    .await;
    core.initialize().await?;
    let core_versions = core
        .check_version()
        .await
        .map(|v| vec![v])
        .unwrap_or_default();
    let mut transport = None;
    if transport_configured {
        match tonic_transport::TonicAgentTransport::connect_with_backoff(&config, 5).await {
            Ok(mut client) => {
                if agent_id.is_none() {
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
                    match client.register(registration).await {
                        Ok(id) => {
                            identity::AgentIdentity {
                                agent_id: id.clone(),
                                node_id: node_uuid,
                                public_key: public_key.clone(),
                                ca_cert_path: config.ca_cert_path.clone(),
                                client_cert_path: config.client_cert_path.clone(),
                                client_key_path: config.client_key_path.clone(),
                            }
                            .persist(&config.identity_path)?;
                            agent_id = Some(id);
                        }
                        Err(error) => warn!(%error, "agent registration failed"),
                    }
                }
                if let Some(id) = agent_id.clone() {
                    transport = Some((client, id));
                }
            }
            Err(error) => warn!(%error, "control-plane connection failed; serving local config"),
        }
    }
    info!(node_id = %node_id, core_state = core.core_state(), "Cyberboard agent started");
    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut supervisor_ticker = interval(Duration::from_secs(2));
    supervisor_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut pending: HashMap<(u64, String), ReportApplyResultRequest> = HashMap::new();
    let mut terminal: HashSet<(u64, String)> = HashSet::new();
    let mut backoff = Duration::from_secs(1);
    let mut healthy_since = Some(std::time::Instant::now());
    let mut crashed_since = None;
    loop {
        tokio::select! {
            _ = supervisor_ticker.tick() => {
                core.supervise_once().await;
                if core.core_state() == "running" {
                    if healthy_since.is_some_and(|since| since.elapsed() >= Duration::from_secs(60)) { backoff = Duration::from_secs(1); }
                } else if core.core_state() == "crashed" {
                    let crashed = *crashed_since.get_or_insert_with(std::time::Instant::now);
                    healthy_since = None;
                    tokio::time::sleep(backoff).await;
                    match core.restart().await {
                        Ok(true) => { healthy_since = Some(std::time::Instant::now()); crashed_since = None; }
                        _ => { backoff = (backoff * 2).min(Duration::from_secs(60)); }
                    }
                    if crashed.elapsed() >= Duration::from_secs(60) { backoff = Duration::from_secs(1); }
                }
            }
            _ = ticker.tick() => {
                if transport.is_none() && transport_configured {
                    if let Some(id) = agent_id.clone() {
                        if let Ok(client) = tonic_transport::TonicAgentTransport::connect_with_backoff(&config, 1).await { transport = Some((client, id)); }
                    }
                }
                if let Some((client, id)) = transport.as_mut() {
                    let outcome = reconcile_once(client, &mut core, trusted_key.as_ref(), &node_id, id, &public_key, &core_versions, &mut pending, &mut terminal).await;
                    if let Err(error) = outcome { warn!(%error, "agent reconciliation failed"); transport = None; }
                }
            }
            signal = shutdown_signal() => {
                if let Err(error) = signal { warn!(%error, "shutdown signal error"); }
                info!("shutdown signal received");
                core.shutdown().await;
                break;
            }
        }
    }
    Ok(())
}

type AgentFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;
trait AgentTransport {
    fn heartbeat<'a>(&'a mut self, request: HeartbeatRequest)
    -> AgentFuture<'a, HeartbeatResponse>;
    fn release<'a>(
        &'a mut self,
        request: GetReleaseManifestRequest,
    ) -> AgentFuture<'a, cyberboard_agent_protocol::generated::ReleaseManifestResponse>;
    fn desired<'a>(
        &'a mut self,
        request: GetDesiredStateRequest,
    ) -> AgentFuture<'a, DesiredStateResponse>;
    fn report_apply<'a>(&'a mut self, request: ReportApplyResultRequest) -> AgentFuture<'a, ()>;
    fn report_upgrade<'a>(&'a mut self, request: ReportUpgradeResultRequest)
    -> AgentFuture<'a, ()>;
}
impl AgentTransport for tonic_transport::TonicAgentTransport {
    fn heartbeat<'a>(&'a mut self, r: HeartbeatRequest) -> AgentFuture<'a, HeartbeatResponse> {
        Box::pin(async move { self.heartbeat_response(r).await.map_err(|e| e.to_string()) })
    }
    fn release<'a>(
        &'a mut self,
        r: GetReleaseManifestRequest,
    ) -> AgentFuture<'a, cyberboard_agent_protocol::generated::ReleaseManifestResponse> {
        Box::pin(async move { self.release_manifest(r).await.map_err(|e| e.to_string()) })
    }
    fn desired<'a>(
        &'a mut self,
        r: GetDesiredStateRequest,
    ) -> AgentFuture<'a, DesiredStateResponse> {
        Box::pin(async move { self.desired_state(r).await.map_err(|e| e.to_string()) })
    }
    fn report_apply<'a>(&'a mut self, r: ReportApplyResultRequest) -> AgentFuture<'a, ()> {
        Box::pin(async move { self.report_apply(r).await.map_err(|e| e.to_string()) })
    }
    fn report_upgrade<'a>(&'a mut self, r: ReportUpgradeResultRequest) -> AgentFuture<'a, ()> {
        Box::pin(async move { self.report_upgrade(r).await.map_err(|e| e.to_string()) })
    }
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_once<T: AgentTransport>(
    client: &mut T,
    core: &mut runtime::CoreSupervisor,
    trusted_key: Option<&VerifyingKey>,
    node_id: &str,
    agent_id: &str,
    public_key: &str,
    core_versions: &[String],
    pending: &mut HashMap<(u64, String), ReportApplyResultRequest>,
    terminal: &mut HashSet<(u64, String)>,
) -> Result<(), String> {
    let now = unix_now();
    let state = core.state().clone();
    let heartbeat = HeartbeatRequest {
        agent_id: agent_id.into(),
        node_id: node_id.into(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        core_versions: core_versions.to_vec(),
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        current_config_revision: if state.generation == 0 {
            String::new()
        } else {
            state.generation.to_string()
        },
        core_state: core.core_state().into(),
        memory_bytes: 0,
        disk_free_bytes: runtime::disk_free_bytes(
            core.config_path()
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        ),
        cpu_percent: 0.0,
        unix_time: now,
        nonce: uuid::Uuid::new_v4().to_string(),
        agent_public_key: public_key.into(),
    };
    let desired_hint = client
        .heartbeat(heartbeat)
        .await
        .map_err(|e| format!("heartbeat: {e}"))?
        .desired_state_revision;
    let manifest = client
        .release(GetReleaseManifestRequest {
            agent_id: agent_id.into(),
            node_id: node_id.into(),
            current_agent_version: env!("CARGO_PKG_VERSION").into(),
            agent_public_key: public_key.into(),
        })
        .await;
    if let Ok(manifest) = manifest {
        if !manifest.version.is_empty() && manifest.version != env!("CARGO_PKG_VERSION") {
            let validation = validate_release_manifest(&manifest);
            let _ = client
                .report_upgrade(ReportUpgradeResultRequest {
                    agent_id: agent_id.into(),
                    node_id: node_id.into(),
                    target_version: manifest.version,
                    success: validation.is_ok(),
                    error_code: if validation.is_ok() {
                        "automatic_upgrade_disabled"
                    } else {
                        "invalid_release_manifest"
                    }
                    .into(),
                    error_message: validation
                        .err()
                        .unwrap_or_else(|| "automatic binary replacement is disabled".into()),
                    agent_public_key: public_key.into(),
                })
                .await;
        }
    }
    for key in pending.keys().cloned().collect::<Vec<_>>() {
        if let Some(report) = pending.get_mut(&key) {
            report.retry_count = report.retry_count.saturating_add(1);
            let delivered = client.report_apply(report.clone()).await.is_ok();
            let exhausted = !delivered && report.retry_count >= 2;
            if delivered || exhausted {
                pending.remove(&key);
                terminal.insert(key);
            }
        }
    }
    if !desired_hint.is_empty() && desired_hint == state.generation.to_string() {
        return Ok(());
    }
    let response = client
        .desired(GetDesiredStateRequest {
            agent_id: agent_id.into(),
            node_id: node_id.into(),
            current_generation: state.generation.to_string(),
            current_content_hash: state.content_hash.clone(),
            last_applied_generation: state.generation,
            agent_public_key: public_key.into(),
        })
        .await
        .map_err(|e| format!("desired state: {e}"))?;
    if response.signed_config.is_empty() {
        return Ok(());
    }
    let envelope: SignedConfigEnvelope = match serde_json::from_slice(&response.signed_config) {
        Ok(value) => value,
        Err(_) => {
            return report_rejection(
                client,
                response,
                node_id,
                agent_id,
                public_key,
                state,
                "invalid_envelope",
                pending,
                terminal,
            )
            .await;
        }
    };
    let hash = hex_hash(&envelope.payload);
    let pair = (envelope.generation, hash.clone());
    if terminal.contains(&pair) || pending.contains_key(&pair) {
        return Ok(());
    }
    let rejection = validate_envelope(&envelope, &response, node_id, trusted_key, unix_now());
    let (phase, error_code, error_message, apply_hash, cas_ok) = if let Some(code) = rejection {
        (
            "rejected",
            code.to_owned(),
            "desired state failed trust validation".to_owned(),
            state.content_hash.clone(),
            true,
        )
    } else if envelope.generation < state.generation {
        (
            "rejected",
            "stale_generation".into(),
            "desired generation is older than local state".into(),
            state.content_hash.clone(),
            true,
        )
    } else if envelope.generation == state.generation && hash != state.content_hash {
        (
            "rejected",
            "generation_conflict".into(),
            "generation already applied with a different hash".into(),
            state.content_hash.clone(),
            true,
        )
    } else if envelope.generation == state.generation {
        return Ok(());
    } else {
        let cas = response.expected_previous_hash.is_empty()
            || response.expected_previous_hash == state.content_hash;
        if !cas {
            warn!(
                generation = envelope.generation,
                "expected previous hash differs; applying advisory mismatch"
            );
        }
        let result = core
            .apply(&envelope.payload, envelope.generation, &hash)
            .await;
        (
            result.phase,
            result.error_code,
            result.error_message,
            result.state.content_hash,
            cas,
        )
    };
    let report = ReportApplyResultRequest {
        agent_id: agent_id.into(),
        node_id: node_id.into(),
        generation: envelope.generation.to_string(),
        previous_hash: state.content_hash.clone(),
        applied_hash: apply_hash,
        phase: phase.into(),
        error_code,
        error_message: error_message.chars().take(512).collect(),
        retry_count: 0,
        unix_time: unix_now(),
        expected_previous_hash: response.expected_previous_hash,
        compare_and_swap_ok: cas_ok,
        agent_public_key: public_key.into(),
    };
    let pair = (envelope.generation, hash);
    if client.report_apply(report.clone()).await.is_err() {
        pending.insert(pair, report);
    } else {
        terminal.insert(pair);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn report_rejection<T: AgentTransport>(
    client: &mut T,
    response: DesiredStateResponse,
    node_id: &str,
    agent_id: &str,
    public_key: &str,
    state: runtime::AppliedState,
    code: &str,
    pending: &mut HashMap<(u64, String), ReportApplyResultRequest>,
    terminal: &mut HashSet<(u64, String)>,
) -> Result<(), String> {
    let generation = response
        .generation
        .parse::<u64>()
        .unwrap_or(response.generation_number);
    let key = (generation, response.content_hash.clone());
    if terminal.contains(&key) || pending.contains_key(&key) {
        return Ok(());
    }
    let report = ReportApplyResultRequest {
        agent_id: agent_id.into(),
        node_id: node_id.into(),
        generation: response.generation,
        previous_hash: state.content_hash.clone(),
        applied_hash: state.content_hash,
        phase: "rejected".into(),
        error_code: code.into(),
        error_message: "signed desired state envelope is invalid".into(),
        retry_count: 0,
        unix_time: unix_now(),
        expected_previous_hash: response.expected_previous_hash,
        compare_and_swap_ok: true,
        agent_public_key: public_key.into(),
    };
    if client.report_apply(report.clone()).await.is_err() {
        pending.insert(key, report);
    } else {
        terminal.insert(key);
    }
    Ok(())
}

fn validate_envelope(
    envelope: &SignedConfigEnvelope,
    response: &DesiredStateResponse,
    node_id: &str,
    key: Option<&VerifyingKey>,
    now: i64,
) -> Option<&'static str> {
    let hash = hex_hash(&envelope.payload);
    if hash != envelope.content_hash
        || (!response.content_hash.is_empty() && response.content_hash != envelope.content_hash)
    {
        return Some("content_hash_mismatch");
    }
    let Some(key) = key else {
        return Some("signature_invalid");
    };
    let Ok(signature) = Signature::from_slice(&envelope.signature) else {
        return Some("signature_invalid");
    };
    if key.verify(&envelope.canonical_bytes(), &signature).is_err() {
        return Some("signature_invalid");
    }
    if envelope.target_node.to_string() != node_id {
        return Some("target_mismatch");
    }
    if envelope.generation.to_string() != response.generation
        || (response.generation_number != 0 && response.generation_number != envelope.generation)
    {
        return Some("generation_mismatch");
    }
    if envelope.issued_at > now.saturating_add(60) {
        return Some("envelope_not_yet_valid");
    }
    if envelope.expires_at < now.saturating_sub(60) || envelope.expires_at < envelope.issued_at {
        return Some("envelope_expired");
    }
    None
}

fn parse_trusted_key(encoded: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = BASE64
        .decode(encoded)?
        .try_into()
        .map_err(|_| "trusted key must decode to 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
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
    BASE64.encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes())
}
fn validate_release_manifest(
    manifest: &cyberboard_agent_protocol::generated::ReleaseManifestResponse,
) -> Result<(), String> {
    if manifest.artifact_url.trim().is_empty() {
        return Err("artifact_url is empty".into());
    }
    if manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("sha256 must be a 64-character hexadecimal digest".into());
    }
    if manifest.signature.trim().is_empty() || manifest.signing_key_id.trim().is_empty() {
        return Err("signature and signing_key_id are required".into());
    }
    Ok(())
}
async fn shutdown_signal() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
mod reconciliation_tests {
    use super::*;
    use cyberboard_agent_protocol::generated::ReleaseManifestResponse;
    use cyberboard_config_compiler::SignedConfigEnvelope;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

    struct FakeTransport {
        desired: DesiredStateResponse,
        heartbeats: Vec<HeartbeatRequest>,
        reports: Vec<ReportApplyResultRequest>,
        fail_first_report: bool,
    }
    impl AgentTransport for FakeTransport {
        fn heartbeat<'a>(
            &'a mut self,
            request: HeartbeatRequest,
        ) -> AgentFuture<'a, HeartbeatResponse> {
            self.heartbeats.push(request);
            Box::pin(async { Ok(HeartbeatResponse::default()) })
        }
        fn release<'a>(
            &'a mut self,
            _: GetReleaseManifestRequest,
        ) -> AgentFuture<'a, ReleaseManifestResponse> {
            Box::pin(async { Ok(ReleaseManifestResponse::default()) })
        }
        fn desired<'a>(
            &'a mut self,
            _: GetDesiredStateRequest,
        ) -> AgentFuture<'a, DesiredStateResponse> {
            let response = self.desired.clone();
            Box::pin(async move { Ok(response) })
        }
        fn report_apply<'a>(
            &'a mut self,
            request: ReportApplyResultRequest,
        ) -> AgentFuture<'a, ()> {
            self.reports.push(request);
            let fail = std::mem::take(&mut self.fail_first_report);
            Box::pin(async move {
                if fail {
                    Err("temporary report failure".into())
                } else {
                    Ok(())
                }
            })
        }
        fn report_upgrade<'a>(&'a mut self, _: ReportUpgradeResultRequest) -> AgentFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    fn fake_core(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("fake-core");
        fs::write(&path, "#!/bin/sh\ncase \"$1\" in\ncheck) exit 0 ;;\nrun) trap ':' HUP; while :; do sleep 0.02; done ;;\nesac\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn reports_once_and_retries_delivery_with_applied_heartbeat() {
        let dir = tempfile::tempdir().unwrap();
        let node = uuid::Uuid::from_u128(44);
        let signing = SigningKey::generate(&mut OsRng);
        let payload = br#"{"inbounds":[],"outbounds":[]}"#.to_vec();
        let now = unix_now();
        let envelope = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            1,
            now - 1,
            now + 300,
            payload.clone(),
        );
        let hash = hex_hash(&payload);
        let desired = DesiredStateResponse {
            generation: "1".into(),
            signed_config: serde_json::to_vec(&envelope).unwrap(),
            content_hash: hash,
            generation_number: 1,
            expected_previous_hash: String::new(),
            ..Default::default()
        };
        let mut transport = FakeTransport {
            desired,
            heartbeats: Vec::new(),
            reports: Vec::new(),
            fail_first_report: true,
        };
        let mut core = runtime::CoreSupervisor::new(
            fake_core(dir.path()),
            dir.path().join("config.json"),
            Duration::from_millis(20),
        )
        .await;
        core.initialize().await.unwrap();
        let node_id = node.to_string();
        let key = signing.verifying_key();
        let mut pending = HashMap::new();
        let mut terminal = HashSet::new();
        reconcile_once(
            &mut transport,
            &mut core,
            Some(&key),
            &node_id,
            "agent",
            "pub",
            &[],
            &mut pending,
            &mut terminal,
        )
        .await
        .unwrap();
        assert_eq!(core.state().generation, 1);
        assert_eq!(transport.reports.len(), 1);
        assert_eq!(transport.reports[0].phase, "applied");
        reconcile_once(
            &mut transport,
            &mut core,
            Some(&key),
            &node_id,
            "agent",
            "pub",
            &[],
            &mut pending,
            &mut terminal,
        )
        .await
        .unwrap();
        assert_eq!(transport.heartbeats[1].current_config_revision, "1");
        assert_eq!(transport.reports.len(), 2);
        assert_eq!(transport.reports[1].retry_count, 1);
        assert!(pending.is_empty());
        core.shutdown().await;
    }
}
