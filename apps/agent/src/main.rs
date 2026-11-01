use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use cyberboard_agent_protocol::generated::{
    DesiredStateResponse, GetDesiredStateRequest, GetReleaseManifestRequest, HeartbeatRequest,
    HeartbeatResponse, RegisterAgentRequest, ReportApplyResultRequest, ReportUpgradeResultRequest,
};
use cyberboard_config::AgentConfig;
use cyberboard_config_compiler::{SignedConfigEnvelope, hex_hash};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{info, warn};

use state::ReconcileState;

mod identity;
mod runtime;
mod state;
mod tonic_transport;
mod usage;

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }
    async fn recv(&mut self) {
        tokio::select! { _ = self.interrupt.recv() => {}, _ = self.terminate.recv() => {} }
    }
}

#[cfg(not(unix))]
struct ShutdownSignals {
    ctrl_c: Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>>,
}

#[cfg(not(unix))]
impl ShutdownSignals {
    fn new() -> Self {
        Self {
            ctrl_c: Box::pin(tokio::signal::ctrl_c()),
        }
    }
    async fn recv(&mut self) {
        let _ = self.ctrl_c.as_mut().await;
    }
}

struct RestartBackoff {
    delay: Duration,
    next_restart_at: Option<Instant>,
    healthy_since: Option<Instant>,
}

impl RestartBackoff {
    fn new(now: Instant) -> Self {
        Self {
            delay: Duration::from_secs(1),
            next_restart_at: None,
            healthy_since: Some(now),
        }
    }
    fn on_crash(&mut self, now: Instant) -> Instant {
        self.healthy_since = None;
        *self.next_restart_at.get_or_insert(now + self.delay)
    }
    fn restart_due(&self, now: Instant) -> bool {
        self.next_restart_at.is_some_and(|deadline| now >= deadline)
    }
    fn on_restart_failed(&mut self, now: Instant) {
        self.delay = (self.delay * 2).min(Duration::from_secs(60));
        self.next_restart_at = Some(now + self.delay);
        self.healthy_since = None;
    }
    fn on_restart_started(&mut self, now: Instant) {
        self.next_restart_at = None;
        self.healthy_since = Some(now);
    }
    fn on_supervisor_tick(&mut self, now: Instant) {
        if self
            .healthy_since
            .is_some_and(|since| now.duration_since(since) >= Duration::from_secs(60))
        {
            self.delay = Duration::from_secs(1);
        }
    }
}

struct ReconcileContext<'a> {
    node_id: &'a str,
    agent_id: &'a str,
    public_key: &'a str,
    core_versions: &'a [String],
    trusted_key: Option<&'a VerifyingKey>,
}

fn core_version_list(line: Option<String>) -> Vec<String> {
    line.and_then(|line| {
        line.strip_prefix("sing-box version ")
            .map(|version| format!("sing-box/{version}"))
    })
    .map(|version| vec![version])
    .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cyberboard_observability::init("cyberboard_agent");
    #[cfg(unix)]
    let mut shutdown = ShutdownSignals::new()?;
    #[cfg(not(unix))]
    let mut shutdown = ShutdownSignals::new();
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
    let durable_state = state::StateStore::load(
        std::path::PathBuf::from(&config.core_config_path).with_extension("state"),
    );
    let mut core = runtime::CoreSupervisor::new_with_state_store(
        &config.core_binary,
        &config.core_config_path,
        Duration::from_millis(config.health_grace_ms),
        durable_state.clone(),
    )
    .await;
    core.initialize().await?;
    let core_versions = core_version_list(core.check_version().await);
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
    let v2ray_api_supported = runtime::binary_has_v2ray_api(std::path::Path::new(&config.core_binary)).await;
    if !v2ray_api_supported {
        warn!("sing-box binary lacks with_v2ray_api; configs containing experimental.v2ray_api will fail sing-box check and be rolled back");
    }
    if let Some(id) = agent_id.clone() {
        tokio::spawn(usage::run_reporting_loop(
            config.clone(),
            id,
            node_id.clone(),
            public_key.clone(),
            core.config_path().to_path_buf(),
            v2ray_api_supported,
        ));
    } else {
        warn!("usage reporting is unavailable until the Agent is registered");
    }
    info!(node_id = %node_id, core_state = core.core_state(), "Cyberboard agent started");
    let mut ticker = interval(Duration::from_secs(config.interval_secs));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut supervisor_ticker = interval(Duration::from_secs(2));
    supervisor_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reconcile_state = ReconcileState::new(durable_state);
    let mut restart = RestartBackoff::new(Instant::now());
    if core.core_state() != "running" {
        restart.healthy_since = None;
        restart.next_restart_at = Some(Instant::now());
    }
    loop {
        tokio::select! {
            _ = supervisor_ticker.tick() => {
                core.supervise_once().await;
                let now = Instant::now();
                restart.on_supervisor_tick(now);
                if core.core_state() == "crashed" {
                    restart.on_crash(now);
                    if restart.restart_due(now) {
                        match core.restart().await {
                            Ok(()) => restart.on_restart_started(Instant::now()),
                            Err(_) => restart.on_restart_failed(Instant::now()),
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                if transport.is_none() && transport_configured {
                    if let Some(id) = agent_id.clone() {
                        if let Ok(client) = tonic_transport::TonicAgentTransport::connect_with_backoff(&config, 1).await { transport = Some((client, id)); }
                    }
                }
                if let Some((client, id)) = transport.as_mut() {
                    let context = ReconcileContext { node_id: &node_id, agent_id: id, public_key: &public_key, core_versions: &core_versions, trusted_key: trusted_key.as_ref() };
                    let outcome = reconcile_once(client, &mut core, &context, &mut reconcile_state).await;
                    if let Err(error) = outcome { warn!(%error, "agent reconciliation failed"); transport = None; }
                }
            }
            _ = shutdown.recv() => {
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

async fn reconcile_once<T: AgentTransport>(
    client: &mut T,
    core: &mut runtime::CoreSupervisor,
    context: &ReconcileContext<'_>,
    reports: &mut ReconcileState,
) -> Result<(), String> {
    let ReconcileContext {
        node_id,
        agent_id,
        public_key,
        core_versions,
        trusted_key,
    } = context;
    let node_id = *node_id;
    let agent_id = *agent_id;
    let public_key = *public_key;
    let core_versions = *core_versions;
    let trusted_key = *trusted_key;
    let now = unix_now();
    let state = core.state().clone();
    let mut process_ids = vec![std::process::id()];
    if let Some(pid) = core.process_id() {
        process_ids.push(pid);
    }
    let metrics = runtime::process_metrics(&process_ids).await;
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
        memory_bytes: metrics.as_ref().map(|value| value.memory_bytes),
        disk_free_bytes: runtime::disk_free_bytes(
            core.config_path()
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
        ),
        cpu_percent: metrics.map(|value| value.cpu_percent),
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
    for (result, report) in reports.pending() {
        if client.report_apply(report).await.is_ok() {
            reports.confirm(&result);
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
            let generation = response
                .generation
                .parse()
                .unwrap_or(response.generation_number);
            let key = (
                generation,
                if response.content_hash.is_empty() {
                    hex_hash(&response.signed_config)
                } else {
                    response.content_hash.clone()
                },
                "invalid_envelope".to_owned(),
            );
            if !reports.has_report(key.0, &key.1, &key.2) {
                let report = ReportApplyResultRequest {
                    agent_id: (*agent_id).into(),
                    node_id: (*node_id).into(),
                    generation: generation.to_string(),
                    previous_hash: state.content_hash.clone(),
                    applied_hash: state.content_hash.clone(),
                    phase: "rejected".into(),
                    error_code: "invalid_envelope".into(),
                    error_message: "signed desired state envelope is invalid".into(),
                    retry_count: 0,
                    unix_time: unix_now(),
                    expected_previous_hash: response.expected_previous_hash,
                    compare_and_swap_ok: true,
                    agent_public_key: (*public_key).into(),
                };
                let confirmed = client.report_apply(report.clone()).await.is_ok();
                reports.record(&report, &key.1, confirmed);
            }
            return Ok(());
        }
    };
    let hash = hex_hash(&envelope.payload);
    let pair = (envelope.generation, hash.clone());
    if reports.has_terminal(pair.0, &pair.1) {
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
        let result = if let Some(error_code) = core.is_known_failure(envelope.generation, &hash) {
            runtime::ApplyOutcome {
                phase: "failed",
                error_code,
                error_message: "desired configuration previously failed and was not retried".into(),
                state: state.clone(),
            }
        } else {
            core.apply(&envelope.payload, envelope.generation, &hash)
                .await
        };
        (
            result.phase,
            result.error_code,
            result.error_message,
            result.state.content_hash,
            cas,
        )
    };
    if phase == "rejected" && reports.has_report(envelope.generation, &hash, &error_code) {
        return Ok(());
    }
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
    let confirmed = client.report_apply(report.clone()).await.is_ok();
    reports.record(&report, &pair.1, confirmed);
    Ok(())
}

fn validate_envelope(
    envelope: &SignedConfigEnvelope,
    response: &DesiredStateResponse,
    node_id: &str,
    key: Option<&VerifyingKey>,
    now: i64,
) -> Option<&'static str> {
    if !response.content_hash.is_empty() && response.content_hash != envelope.content_hash {
        return Some("content_hash_mismatch");
    }
    let Some(key) = key else {
        return Some("signature_invalid");
    };
    match envelope.verify_with_skew(key, now, 60) {
        Ok(()) => {}
        Err(cyberboard_config_compiler::CompileError::InvalidEnvelope) => {
            return Some("invalid_envelope");
        }
        Err(cyberboard_config_compiler::CompileError::ContentHashMismatch) => {
            return Some("content_hash_mismatch");
        }
        Err(cyberboard_config_compiler::CompileError::SignatureMismatch) => {
            return Some("signature_invalid");
        }
        Err(cyberboard_config_compiler::CompileError::EnvelopeNotYetValid) => {
            return Some("envelope_not_yet_valid");
        }
        Err(cyberboard_config_compiler::CompileError::EnvelopeExpired) => {
            return Some("envelope_expired");
        }
        Err(_) => return Some("invalid_envelope"),
    }
    if envelope.target_node.to_string() != node_id {
        return Some("target_mismatch");
    }
    if envelope.generation.to_string() != response.generation
        || (response.generation_number != 0 && response.generation_number != envelope.generation)
    {
        return Some("generation_mismatch");
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
#[cfg(test)]
mod restart_backoff_tests {
    use super::RestartBackoff;
    use std::time::{Duration, Instant};

    #[test]
    fn formats_sing_box_version_for_heartbeat() {
        assert_eq!(
            super::core_version_list(Some("sing-box version 1.14.4".into())),
            ["sing-box/1.14.4"]
        );
        assert!(super::core_version_list(None).is_empty());
    }

    #[test]
    fn backoff_doubles_caps_and_resets_after_healthy_uptime() {
        let start = Instant::now();
        let mut policy = RestartBackoff::new(start);
        let first = policy.on_crash(start);
        assert_eq!(first.duration_since(start), Duration::from_secs(1));
        policy.on_restart_failed(first);
        assert_eq!(policy.delay, Duration::from_secs(2));
        let second = policy.on_crash(first);
        policy.on_restart_failed(second);
        assert_eq!(policy.delay, Duration::from_secs(4));
        let mut now = second;
        for _ in 0..8 {
            let deadline = policy.on_crash(now);
            policy.on_restart_failed(deadline);
            now = deadline;
        }
        assert_eq!(policy.delay, Duration::from_secs(60));
        policy.on_restart_started(now);
        policy.on_supervisor_tick(now + Duration::from_secs(59));
        assert_eq!(policy.delay, Duration::from_secs(60));
        policy.on_crash(now + Duration::from_secs(59));
        policy.on_supervisor_tick(now + Duration::from_secs(120));
        assert_eq!(policy.delay, Duration::from_secs(60));
        policy.on_restart_started(now + Duration::from_secs(121));
        policy.on_supervisor_tick(now + Duration::from_secs(181));
        assert_eq!(policy.delay, Duration::from_secs(1));
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
        fs::write(&path, "#!/bin/sh\ncase \"$1\" in\ncheck) echo check >> \"$0.checks\"; grep -q fail_check \"$3\" && exit 1; exit 0 ;;\nrun) trap ':' HUP; while :; do sleep 0.02; done ;;\nesac\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn trust_validation_uses_library_precedence_and_skew_boundaries() {
        let signing = SigningKey::generate(&mut OsRng);
        let key = signing.verifying_key();
        let node = uuid::Uuid::from_u128(44);
        let now = 1_000;
        let make = |target, generation, issued, expires| {
            SignedConfigEnvelope::sign(
                &signing,
                "test",
                target,
                generation,
                issued,
                expires,
                b"{}".to_vec(),
            )
        };
        let response_for = |envelope: &SignedConfigEnvelope| DesiredStateResponse {
            generation: envelope.generation.to_string(),
            content_hash: envelope.content_hash.clone(),
            generation_number: envelope.generation,
            ..Default::default()
        };
        let mut bad_signature_and_future = make(node, 1, now + 120, now + 300);
        bad_signature_and_future.signature[0] ^= 1;
        assert_eq!(
            validate_envelope(
                &bad_signature_and_future,
                &response_for(&bad_signature_and_future),
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("signature_invalid")
        );
        let mut bad_hash_and_signature = make(node, 1, now, now + 300);
        bad_hash_and_signature.content_hash = "wrong".into();
        bad_hash_and_signature.signature[0] ^= 1;
        assert_eq!(
            validate_envelope(
                &bad_hash_and_signature,
                &response_for(&bad_hash_and_signature),
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("content_hash_mismatch")
        );
        let expired_wrong_target = make(uuid::Uuid::from_u128(99), 2, now - 300, now - 120);
        let mut expired_response = response_for(&expired_wrong_target);
        expired_response.generation = "1".into();
        assert_eq!(
            validate_envelope(
                &expired_wrong_target,
                &expired_response,
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("envelope_expired")
        );
        let future_wrong_generation = make(node, 2, now + 120, now + 300);
        let mut future_response = response_for(&future_wrong_generation);
        future_response.generation = "1".into();
        assert_eq!(
            validate_envelope(
                &future_wrong_generation,
                &future_response,
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("envelope_not_yet_valid")
        );
        let generation_mismatch = make(node, 1, now, now + 300);
        let mut generation_response = response_for(&generation_mismatch);
        generation_response.generation = "2".into();
        assert_eq!(
            validate_envelope(
                &generation_mismatch,
                &generation_response,
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("generation_mismatch")
        );
        let mut invalid_len = make(node, 1, now, now + 300);
        invalid_len.signature.clear();
        assert_eq!(
            validate_envelope(
                &invalid_len,
                &response_for(&invalid_len),
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("invalid_envelope")
        );
        let future_30 = make(node, 1, now + 30, now + 300);
        assert_eq!(
            validate_envelope(
                &future_30,
                &response_for(&future_30),
                &node.to_string(),
                Some(&key),
                now
            ),
            None
        );
        let expiring_30 = make(node, 1, now - 300, now - 30);
        assert_eq!(
            validate_envelope(
                &expiring_30,
                &response_for(&expiring_30),
                &node.to_string(),
                Some(&key),
                now
            ),
            None
        );
        let future_120 = make(node, 1, now + 120, now + 300);
        assert_eq!(
            validate_envelope(
                &future_120,
                &response_for(&future_120),
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("envelope_not_yet_valid")
        );
        let mut response_hash_mismatch = response_for(&future_30);
        response_hash_mismatch.content_hash = "different-response-hash".into();
        assert_eq!(
            validate_envelope(
                &future_30,
                &response_hash_mismatch,
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("content_hash_mismatch")
        );
        let target_and_generation_mismatch = make(uuid::Uuid::from_u128(99), 2, now, now + 300);
        let mut target_response = response_for(&target_and_generation_mismatch);
        target_response.generation = "1".into();
        assert_eq!(
            validate_envelope(
                &target_and_generation_mismatch,
                &target_response,
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("target_mismatch")
        );
        let expiring_120 = make(node, 1, now - 300, now - 120);
        assert_eq!(
            validate_envelope(
                &expiring_120,
                &response_for(&expiring_120),
                &node.to_string(),
                Some(&key),
                now
            ),
            Some("envelope_expired")
        );
    }

    #[test]
    fn release_manifest_validation_rejects_missing_integrity_fields() {
        let manifest = ReleaseManifestResponse {
            version: "0.2.0".into(),
            artifact_url: "https://example.invalid/agent".into(),
            sha256: "bad".into(),
            signature: String::new(),
            signing_key_id: String::new(),
            mandatory: false,
        };
        assert!(validate_release_manifest(&manifest).is_err());
    }

    fn desired_response(
        envelope: &SignedConfigEnvelope,
        expected_previous_hash: &str,
    ) -> DesiredStateResponse {
        DesiredStateResponse {
            generation: envelope.generation.to_string(),
            signed_config: serde_json::to_vec(envelope).unwrap(),
            content_hash: envelope.content_hash.clone(),
            generation_number: envelope.generation,
            expected_previous_hash: expected_previous_hash.into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn known_failed_config_is_skipped_after_restart_but_newer_generation_runs() {
        let dir = tempfile::tempdir().unwrap();
        let node = uuid::Uuid::from_u128(77);
        let signing = SigningKey::generate(&mut OsRng);
        let key = signing.verifying_key();
        let now = unix_now();
        let config = dir.path().join("config.json");
        let binary = fake_core(dir.path());
        let durable = state::StateStore::load(config.with_extension("state"));
        let mut core = runtime::CoreSupervisor::new_with_state_store(
            &binary,
            &config,
            Duration::from_millis(20),
            durable.clone(),
        )
        .await;
        core.initialize().await.unwrap();
        let first = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            1,
            now - 1,
            now + 300,
            b"generation-one".to_vec(),
        );
        assert_eq!(
            core.apply(&first.payload, 1, &first.content_hash)
                .await
                .phase,
            "applied"
        );
        let failed = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            2,
            now - 1,
            now + 300,
            b"fail_check_generation_two".to_vec(),
        );
        let mut transport = FakeTransport {
            desired: desired_response(&failed, ""),
            heartbeats: Vec::new(),
            reports: Vec::new(),
            fail_first_report: false,
        };
        let node_id = node.to_string();
        let context = ReconcileContext {
            node_id: &node_id,
            agent_id: "agent",
            public_key: "pub",
            core_versions: &[],
            trusted_key: Some(&key),
        };
        let mut reports = ReconcileState::new(durable);
        reconcile_once(&mut transport, &mut core, &context, &mut reports)
            .await
            .unwrap();
        assert_eq!(transport.reports.last().unwrap().phase, "failed");
        let checks = std::path::PathBuf::from(format!("{}.checks", binary.display()));
        let count_after_failure = fs::read_to_string(&checks).unwrap().lines().count();
        core.shutdown().await;

        let durable = state::StateStore::load(config.with_extension("state"));
        let mut restarted = runtime::CoreSupervisor::new_with_state_store(
            &binary,
            &config,
            Duration::from_millis(20),
            durable.clone(),
        )
        .await;
        restarted.initialize().await.unwrap();
        let mut reports = ReconcileState::new(durable);
        transport.reports.clear();
        transport.desired = desired_response(&failed, "");
        reconcile_once(&mut transport, &mut restarted, &context, &mut reports)
            .await
            .unwrap();
        assert!(transport.reports.is_empty());
        assert_eq!(
            fs::read_to_string(&checks).unwrap().lines().count(),
            count_after_failure
        );

        let newer = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            3,
            now - 1,
            now + 300,
            b"generation-three".to_vec(),
        );
        transport.desired = desired_response(&newer, "");
        reconcile_once(&mut transport, &mut restarted, &context, &mut reports)
            .await
            .unwrap();
        assert_eq!(transport.reports.last().unwrap().phase, "applied");
        assert_eq!(
            fs::read_to_string(&checks).unwrap().lines().count(),
            count_after_failure + 1
        );
        assert_eq!(restarted.state().generation, 3);
        restarted.shutdown().await;
    }

    #[tokio::test]
    async fn generation_decisions_and_rejected_outcome_revalidation() {
        let dir = tempfile::tempdir().unwrap();
        let node = uuid::Uuid::from_u128(55);
        let signing = SigningKey::generate(&mut OsRng);
        let key = signing.verifying_key();
        let now = unix_now();
        let mut core = runtime::CoreSupervisor::new(
            fake_core(dir.path()),
            dir.path().join("config.json"),
            Duration::from_millis(20),
        )
        .await;
        core.initialize().await.unwrap();
        let first = b"generation-one".to_vec();
        let first_envelope = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            1,
            now - 1,
            now + 300,
            first.clone(),
        );
        assert_eq!(
            core.apply(&first, 1, &hex_hash(&first)).await.phase,
            "applied"
        );
        let mut transport = FakeTransport {
            desired: desired_response(&first_envelope, ""),
            heartbeats: Vec::new(),
            reports: Vec::new(),
            fail_first_report: false,
        };
        let node_id = node.to_string();
        let context = ReconcileContext {
            node_id: &node_id,
            agent_id: "agent",
            public_key: "pub",
            core_versions: &[],
            trusted_key: Some(&key),
        };
        let mut state = ReconcileState::default();
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert!(
            transport.reports.is_empty(),
            "equal generation and hash is a no-op"
        );

        let conflict_payload = b"different-hash".to_vec();
        let conflict = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            1,
            now - 1,
            now + 300,
            conflict_payload,
        );
        transport.desired = desired_response(&conflict, "");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(
            transport.reports.last().unwrap().error_code,
            "generation_conflict"
        );
        let count = transport.reports.len();
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(
            transport.reports.len(),
            count,
            "same rejection code is reported once"
        );

        let stale = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            0,
            now - 1,
            now + 300,
            b"stale".to_vec(),
        );
        transport.desired = desired_response(&stale, "");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(
            transport.reports.last().unwrap().error_code,
            "stale_generation"
        );

        let second_payload = b"generation-two".to_vec();
        let second = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            2,
            now - 1,
            now + 300,
            second_payload.clone(),
        );
        transport.desired = desired_response(&second, "some-other-previous-hash");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(transport.reports.last().unwrap().phase, "applied");
        assert!(!transport.reports.last().unwrap().compare_and_swap_ok);

        let third_payload = b"generation-three".to_vec();
        let mut invalid = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            3,
            now - 1,
            now + 300,
            third_payload.clone(),
        );
        invalid.signature[0] ^= 1;
        transport.desired = desired_response(&invalid, "");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(
            transport.reports.last().unwrap().error_code,
            "signature_invalid"
        );
        let report_count = transport.reports.len();
        let future = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            3,
            now + 120,
            now + 300,
            third_payload.clone(),
        );
        transport.desired = desired_response(&future, "");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(
            transport.reports.last().unwrap().error_code,
            "envelope_not_yet_valid"
        );
        let after_distinct_rejection = transport.reports.len();
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(transport.reports.len(), after_distinct_rejection);
        assert_eq!(after_distinct_rejection, report_count + 1);
        let corrected = SignedConfigEnvelope::sign(
            &signing,
            "test",
            node,
            3,
            now - 1,
            now + 300,
            third_payload.clone(),
        );
        transport.desired = desired_response(&corrected, "");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(transport.reports.len(), report_count + 2);
        assert_eq!(transport.reports.last().unwrap().phase, "applied");
        assert_eq!(core.state().generation, 3);
        core.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_envelope_is_reported_as_invalid_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let node_id = uuid::Uuid::from_u128(88).to_string();
        let desired = DesiredStateResponse {
            generation: "4".into(),
            signed_config: b"not-json".to_vec(),
            content_hash: "declared-hash".into(),
            generation_number: 4,
            ..Default::default()
        };
        let mut transport = FakeTransport {
            desired,
            heartbeats: Vec::new(),
            reports: Vec::new(),
            fail_first_report: false,
        };
        let mut core = runtime::CoreSupervisor::new(
            fake_core(dir.path()),
            dir.path().join("config.json"),
            Duration::from_millis(20),
        )
        .await;
        core.initialize().await.unwrap();
        let context = ReconcileContext {
            node_id: &node_id,
            agent_id: "agent",
            public_key: "pub",
            core_versions: &[],
            trusted_key: None,
        };
        let mut state = ReconcileState::default();
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(transport.reports.len(), 1);
        assert_eq!(transport.reports[0].error_code, "invalid_envelope");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(transport.reports.len(), 1);
        assert!(core.state().content_hash.is_empty());
        core.shutdown().await;
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
        let mut state = ReconcileState::default();
        let context = ReconcileContext {
            node_id: &node_id,
            agent_id: "agent",
            public_key: "pub",
            core_versions: &[],
            trusted_key: Some(&key),
        };
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(core.state().generation, 1);
        assert_eq!(transport.reports.len(), 1);
        assert_eq!(transport.reports[0].phase, "applied");
        reconcile_once(&mut transport, &mut core, &context, &mut state)
            .await
            .unwrap();
        assert_eq!(transport.heartbeats[1].current_config_revision, "1");
        assert_eq!(transport.reports.len(), 2);
        assert_eq!(transport.reports[1].retry_count, 0);
        assert!(state.pending().is_empty());
        core.shutdown().await;
    }
}
