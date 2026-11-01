use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cyberboard_agent_protocol::{
    generated::{
        ReportUsageRequest, UsageCounter as ProtoUsageCounter, UsagePayload as ProtoUsagePayload,
    },
    v2rayapi::{QueryStatsRequest, stats_service_client::StatsServiceClient},
};
use cyberboard_config::AgentConfig;
use prost::Message;
use serde::{Deserialize, Serialize};
use tokio::time::{MissedTickBehavior, interval};
use tonic::{
    Code, Request,
    transport::{Channel, Endpoint},
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::tonic_transport::TonicAgentTransport;

pub const USAGE_PAYLOAD_VERSION: u32 = 1;
pub const USAGE_BUCKET_SECS: i64 = 60;
pub const MAX_QUEUE_BATCHES: usize = 256;
pub const MAX_DEAD_LETTERS: usize = 256;

type CollectorFuture<'a> = Pin<Box<dyn Future<Output = io::Result<UsageSnapshot>> + Send + 'a>>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageSnapshot {
    pub counters: BTreeMap<String, UserCounter>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserCounter {
    pub download_bytes: u64,
    pub upload_bytes: u64,
}

pub trait UsageCollector: Send {
    fn collect(&mut self) -> CollectorFuture<'_>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsageBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub window_start: i64,
    pub window_end: i64,
    pub payload: UsageSnapshot,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DeadLetter {
    batch: UsageBatch,
    code: String,
    message: String,
}

struct DeadLetterStore {
    path: PathBuf,
    entries: Vec<DeadLetter>,
}

impl DeadLetterStore {
    fn open(queue_path: &Path) -> io::Result<Self> {
        let path = queue_path.with_extension("dead-letter.json");
        let entries = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("usage dead letter: {error}"),
                )
            })?
        } else {
            Vec::new()
        };
        Ok(Self { path, entries })
    }

    fn contains(&self, batch_id: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.batch.batch_id == batch_id)
    }

    fn append(&mut self, batch: UsageBatch, code: &str, message: &str) -> io::Result<()> {
        if self.contains(&batch.batch_id) {
            return Ok(());
        }
        let previous = self.entries.clone();
        self.entries.push(DeadLetter {
            batch,
            code: code.to_owned(),
            message: message.chars().take(512).collect(),
        });
        if self.entries.len() > MAX_DEAD_LETTERS {
            self.entries.remove(0);
            warn!(
                max_entries = MAX_DEAD_LETTERS,
                "dropping oldest usage dead letter after capacity was reached"
            );
        }
        if let Err(error) = self.persist() {
            self.entries = previous;
            return Err(error);
        }
        Ok(())
    }

    fn persist(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self.path.with_extension("dead-letter-tmp");
        let bytes = serde_json::to_vec_pretty(&self.entries)
            .map_err(|error| io::Error::other(format!("serialize usage dead letter: {error}")))?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct UsageQueue {
    path: PathBuf,
    disk: QueueDisk,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct QueueDisk {
    version: u32,
    batches: Vec<UsageBatch>,
    #[serde(default)]
    active_window_start: Option<i64>,
    #[serde(default)]
    active_counters: BTreeMap<String, UserCounter>,
    #[serde(default)]
    next_sequence: u64,
}

impl UsageQueue {
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let disk = if path.exists() {
            let disk: QueueDisk = serde_json::from_slice(&fs::read(&path)?).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidData, format!("usage queue: {error}"))
            })?;
            if disk.version != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported usage queue version",
                ));
            }
            disk
        } else {
            QueueDisk {
                version: 1,
                ..QueueDisk::default()
            }
        };
        Ok(Self { path, disk })
    }

    pub fn front(&self) -> Option<&UsageBatch> {
        self.disk.batches.first()
    }

    /// Delta counters are accumulated into the current one-minute wall-clock
    /// bucket and fsynced after every poll. A sing-box or Agent crash can lose
    /// at most one polling interval plus bytes read before the fsync completes.
    /// There is no pre-reload hook, so SIGHUP can lose at most one poll interval.
    pub fn record_delta(&mut self, snapshot: UsageSnapshot, now: i64) -> io::Result<()> {
        let previous = self.disk.clone();
        let result = self.record_delta_inner(snapshot, now);
        if result.is_err() {
            self.disk = previous;
        }
        result
    }

    fn record_delta_inner(&mut self, snapshot: UsageSnapshot, now: i64) -> io::Result<()> {
        let bucket_start = now.div_euclid(USAGE_BUCKET_SECS) * USAGE_BUCKET_SECS;
        if let Some(active) = self.disk.active_window_start {
            if active != bucket_start {
                self.flush_active(bucket_start)?;
            }
        } else {
            self.disk.active_window_start = Some(bucket_start);
        }
        for (username, delta) in snapshot.counters {
            if delta.download_bytes == 0 && delta.upload_bytes == 0 {
                continue;
            }
            let counter = self.disk.active_counters.entry(username).or_default();
            counter.download_bytes = counter
                .download_bytes
                .checked_add(delta.download_bytes)
                .ok_or_else(|| io::Error::other("download byte counter overflow"))?;
            counter.upload_bytes = counter
                .upload_bytes
                .checked_add(delta.upload_bytes)
                .ok_or_else(|| io::Error::other("upload byte counter overflow"))?;
        }
        self.persist()
    }

    pub fn flush_due(&mut self, now: i64) -> io::Result<()> {
        if let Some(active) = self.disk.active_window_start {
            let current_bucket = now.div_euclid(USAGE_BUCKET_SECS) * USAGE_BUCKET_SECS;
            if active < current_bucket {
                self.flush_active(current_bucket)?;
            }
        }
        self.persist()
    }

    fn flush_active(&mut self, end: i64) -> io::Result<()> {
        let Some(start) = self.disk.active_window_start else {
            return Ok(());
        };
        if !self.disk.active_counters.is_empty() {
            let sequence = self.disk.next_sequence;
            self.disk.next_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("usage batch sequence exhausted"))?;
            self.disk.batches.push(UsageBatch {
                batch_id: Uuid::new_v4().to_string(),
                sequence,
                window_start: start,
                window_end: end.max(start + 1),
                payload: UsageSnapshot {
                    counters: std::mem::take(&mut self.disk.active_counters),
                },
            });
            if self.disk.batches.len() > MAX_QUEUE_BATCHES {
                self.disk.batches.remove(0);
                warn!(
                    max_batches = MAX_QUEUE_BATCHES,
                    "dropping oldest usage batch after queue reached capacity"
                );
            }
        }
        self.disk.active_window_start = Some(end);
        Ok(())
    }

    pub fn acknowledge(&mut self, batch_id: &str) -> io::Result<bool> {
        let previous = self.disk.clone();
        let result = self.acknowledge_inner(batch_id);
        if result.is_err() {
            self.disk = previous;
        }
        result
    }

    fn acknowledge_inner(&mut self, batch_id: &str) -> io::Result<bool> {
        let Some(index) = self
            .disk
            .batches
            .iter()
            .position(|batch| batch.batch_id == batch_id)
        else {
            return Ok(false);
        };
        self.disk.batches.remove(index);
        self.persist()?;
        Ok(true)
    }

    fn persist(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = self.path.with_extension("queue-tmp");
        let bytes = serde_json::to_vec_pretty(&self.disk)
            .map_err(|error| io::Error::other(format!("serialize usage queue: {error}")))?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

/// The V2Ray API is plaintext and has no authentication. Reject non-loopback
/// listeners because the API can expose user stats and control operations.
fn v2ray_api_endpoint(path: &Path) -> io::Result<Option<String>> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sing-box config: {error}"),
        )
    })?;
    let Some(listen) = value
        .get("experimental")
        .and_then(|value| value.get("v2ray_api"))
        .and_then(|value| value.get("listen"))
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    let address: SocketAddr = listen.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "experimental.v2ray_api.listen must be host:port",
        )
    })?;
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "V2Ray API listen address must be loopback",
        ));
    }
    Ok(Some(format!("http://{address}")))
}

pub struct V2rayCollector {
    client: StatsServiceClient<Channel>,
}

impl V2rayCollector {
    pub async fn connect(path: &Path) -> io::Result<Option<Self>> {
        let Some(endpoint) = v2ray_api_endpoint(path)? else {
            return Ok(None);
        };
        Self::connect_endpoint(endpoint).await.map(Some)
    }

    async fn connect_endpoint(endpoint: String) -> io::Result<Self> {
        let channel = Endpoint::from_shared(endpoint)
            .map_err(|error| io::Error::other(error.to_string()))?
            .connect_timeout(Duration::from_secs(2))
            .connect()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self {
            client: StatsServiceClient::new(channel),
        })
    }
}

impl UsageCollector for V2rayCollector {
    fn collect(&mut self) -> CollectorFuture<'_> {
        Box::pin(async move {
            let response = self
                .client
                .query_stats(Request::new(QueryStatsRequest {
                    pattern: String::new(),
                    reset: true,
                    patterns: vec!["user>>>".to_owned()],
                    regexp: false,
                }))
                .await
                .map_err(|error| io::Error::other(format!("V2Ray QueryStats: {error}")))?;
            let mut counters: BTreeMap<String, UserCounter> = BTreeMap::new();
            for stat in response.into_inner().stat {
                let Some(rest) = stat.name.strip_prefix("user>>>") else {
                    continue;
                };
                let Some((username, direction)) = rest.rsplit_once(">>>traffic>>>") else {
                    continue;
                };
                if username.is_empty() || stat.value < 0 {
                    continue;
                }
                let counter = counters.entry(username.to_owned()).or_default();
                match direction {
                    "uplink" => counter.upload_bytes = stat.value as u64,
                    "downlink" => counter.download_bytes = stat.value as u64,
                    _ => {}
                }
            }
            Ok(UsageSnapshot { counters })
        })
    }
}

fn to_proto_payload(snapshot: &UsageSnapshot) -> ProtoUsagePayload {
    ProtoUsagePayload {
        version: USAGE_PAYLOAD_VERSION,
        counters: snapshot
            .counters
            .iter()
            .map(|(username, counter)| ProtoUsageCounter {
                username: username.clone(),
                download_bytes: counter.download_bytes,
                upload_bytes: counter.upload_bytes,
            })
            .collect(),
    }
}

pub async fn run_reporting_loop(
    config: AgentConfig,
    agent_id: String,
    node_id: String,
    public_key: String,
    config_path: PathBuf,
    v2ray_api_supported: bool,
) {
    let queue_path = config
        .usage_queue_path
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| config_path.with_extension("usage-queue.json"));
    let mut queue = match UsageQueue::open(&queue_path) {
        Ok(queue) => queue,
        Err(error) => {
            warn!(%error, path = %queue_path.display(), "usage queue could not be opened; traffic reporting is disabled");
            return;
        }
    };
    let mut dead_letters = match DeadLetterStore::open(&queue_path) {
        Ok(store) => store,
        Err(error) => {
            warn!(%error, "usage dead-letter file could not be opened; permanent errors will remain queued");
            DeadLetterStore {
                path: queue_path.with_extension("dead-letter.json"),
                entries: Vec::new(),
            }
        }
    };
    let mut collector: Option<Box<dyn UsageCollector>> = None;
    if !v2ray_api_supported {
        warn!("sing-box binary lacks with_v2ray_api; V2Ray traffic collection is disabled");
    } else {
        match V2rayCollector::connect(&config_path).await {
            Ok(Some(value)) => {
                collector = Some(Box::new(value));
                info!("V2Ray per-user traffic collector enabled");
            }
            Ok(None) => warn!(
                "applied sing-box config has no experimental.v2ray_api.listen; traffic reporting is disabled"
            ),
            Err(error) => {
                warn!(%error, "V2Ray API is unavailable or unsafe; traffic reporting is disabled")
            }
        }
    }
    let mut poller = interval(Duration::from_secs(config.usage_poll_interval_secs));
    poller.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reporter = interval(Duration::from_secs(config.usage_report_interval_secs));
    reporter.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut transport: Option<TonicAgentTransport> = None;

    loop {
        tokio::select! {
            _ = poller.tick() => {
                if collector.is_none() && v2ray_api_supported {
                    match V2rayCollector::connect(&config_path).await {
                        Ok(Some(value)) => collector = Some(Box::new(value)),
                        Ok(None) => {},
                        Err(error) => warn!(%error, "V2Ray API is unavailable or unsafe; traffic collection remains disabled"),
                    }
                }
                if collector.is_some() {
                    let result = collector.as_mut().expect("collector exists").collect().await;
                    match result {
                        Ok(snapshot) => {
                            if let Err(error) = queue.record_delta(snapshot, unix_now()) {
                                warn!(%error, "usage delta could not be persisted");
                            }
                        }
                        Err(error) => {
                            warn!(%error, "V2Ray traffic sample failed; no synthetic usage will be reported");
                            collector = None;
                        }
                    }
                }
            }
            _ = reporter.tick() => {
                if let Err(error) = queue.flush_due(unix_now()) {
                    warn!(%error, "usage bucket could not be persisted");
                }
                while let Some(batch) = queue.front().cloned() {
                    if dead_letters.contains(&batch.batch_id) {
                        if queue.acknowledge(&batch.batch_id).is_err() { break; }
                        continue;
                    }
                    if transport.is_none() {
                        match TonicAgentTransport::connect_with_backoff(&config, 1).await {
                            Ok(client) => transport = Some(client),
                            Err(error) => { warn!(%error, "could not connect to control plane for queued usage report"); break; }
                        }
                    }
                    let request = ReportUsageRequest {
                        agent_id: agent_id.clone(),
                        node_id: node_id.clone(),
                        batch_id: batch.batch_id.clone(),
                        sequence: batch.sequence,
                        window_start: batch.window_start,
                        window_end: batch.window_end,
                        usage_payload: to_proto_payload(&batch.payload).encode_to_vec(),
                        agent_public_key: public_key.clone(),
                    };
                    match transport.as_mut().expect("transport connected").report_usage(request).await {
                        Ok(true) => {
                            if queue.acknowledge(&batch.batch_id).is_err() { break; }
                        }
                        Ok(false) => {
                            error!(batch_id = %batch.batch_id, "control plane rejected usage batch; moving it to dead-letter store");
                            if dead_letters.append(batch.clone(), "rejected", "control plane rejected usage batch").is_err() { break; }
                            if queue.acknowledge(&batch.batch_id).is_err() { break; }
                        }
                        Err(error) if is_dead_letter_code(error.code()) => {
                            let code = format!("{:?}", error.code());
                            error!(batch_id = %batch.batch_id, code, message = %error.message(), "permanent usage report failure moved to dead-letter store");
                            if dead_letters.append(batch.clone(), &code, error.message()).is_err() { break; }
                            if queue.acknowledge(&batch.batch_id).is_err() { break; }
                        }
                        Err(error) => {
                            error!(%error, batch_id = %batch.batch_id, "usage report failed; batch remains queued for retry");
                            transport = None;
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn is_dead_letter_code(code: Code) -> bool {
    code == Code::InvalidArgument
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tempfile::tempdir;

    struct TestCollector(VecDeque<UsageSnapshot>);
    impl UsageCollector for TestCollector {
        fn collect(&mut self) -> CollectorFuture<'_> {
            let snapshot = self.0.pop_front().unwrap();
            Box::pin(async move { Ok(snapshot) })
        }
    }
    fn snapshot(bytes: u64) -> UsageSnapshot {
        UsageSnapshot {
            counters: BTreeMap::from([(
                "user-uuid".into(),
                UserCounter {
                    download_bytes: bytes,
                    upload_bytes: 3,
                },
            )]),
        }
    }
    #[tokio::test]
    async fn test_collector_returns_per_poll_deltas() {
        let mut collector = TestCollector(VecDeque::from([snapshot(40), snapshot(60)]));
        assert_eq!(collector.collect().await.unwrap(), snapshot(40));
        assert_eq!(collector.collect().await.unwrap(), snapshot(60));
    }
    #[test]
    fn queue_accumulates_poll_deltas_and_retries_after_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent-usage.json");
        let mut queue = UsageQueue::open(&path).unwrap();
        queue.record_delta(snapshot(40), 100).unwrap();
        queue.record_delta(snapshot(60), 110).unwrap();
        queue.flush_due(160).unwrap();
        let mut retry = UsageQueue::open(&path).unwrap();
        let batch = retry.front().unwrap().clone();
        assert_eq!(batch.payload.counters["user-uuid"].download_bytes, 100);
        assert!(retry.acknowledge(&batch.batch_id).unwrap());
        assert!(UsageQueue::open(&path).unwrap().front().is_none());
    }
    #[test]
    fn non_loopback_v2ray_api_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(
            &path,
            r#"{"experimental":{"v2ray_api":{"listen":"0.0.0.0:10085"}}}"#,
        )
        .unwrap();
        assert_eq!(
            v2ray_api_endpoint(&path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[test]
    fn permission_denied_stays_queued_but_invalid_argument_moves_to_dead_letter() {
        let dir = tempdir().unwrap();
        let queue_path = dir.path().join("usage-queue.json");
        let mut queue = UsageQueue::open(&queue_path).unwrap();
        queue.record_delta(snapshot(4), 100).unwrap();
        queue.flush_due(160).unwrap();
        let batch = queue.front().unwrap().clone();
        let mut dead_letters = DeadLetterStore::open(&queue_path).unwrap();
        assert!(!is_dead_letter_code(Code::PermissionDenied));
        assert!(queue.front().is_some());
        assert!(!dead_letters.contains(&batch.batch_id));
        assert!(is_dead_letter_code(Code::InvalidArgument));
        dead_letters
            .append(batch.clone(), "InvalidArgument", "bad payload")
            .unwrap();
        queue.acknowledge(&batch.batch_id).unwrap();
        assert!(queue.front().is_none());
        assert!(dead_letters.contains(&batch.batch_id));
    }
}
