use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use cyberboard_agent_protocol::generated::ReportApplyResultRequest;
use prost::Message;
use serde::{Deserialize, Serialize};
use tracing::warn;

const MAX_FAILURES: usize = 128;
const MAX_RESULTS: usize = 256;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppliedState {
    pub generation: u64,
    pub content_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureRecord {
    pub generation: u64,
    pub content_hash: String,
    pub error_code: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TerminalResult {
    pub generation: u64,
    pub content_hash: String,
    pub error_code: String,
    pub report: Vec<u8>,
    pub confirmed: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct AgentState {
    pub current: AppliedState,
    pub previous_successful_config: Option<PathBuf>,
    pub previous_successful: Option<AppliedState>,
    pub failures: Vec<FailureRecord>,
    pub results: Vec<TerminalResult>,
}

#[derive(Clone)]
pub struct StateStore {
    path: PathBuf,
    state: Arc<Mutex<AgentState>>,
}

impl StateStore {
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let state = match fs::read(&path) {
            Ok(bytes) => {
                let is_legacy = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .is_some_and(|value| {
                        value.get("generation").is_some() && value.get("current").is_none()
                    });
                if is_legacy {
                    serde_json::from_slice::<AppliedState>(&bytes)
                        .map(|current| AgentState {
                            current,
                            ..AgentState::default()
                        })
                        .unwrap_or_default()
                } else {
                    match serde_json::from_slice(&bytes) {
                        Ok(state) => state,
                        Err(error) => {
                            warn!(%error, path = %path.display(), "agent state file is corrupt; starting with empty state");
                            AgentState::default()
                        }
                    }
                }
            }

            Err(error) if error.kind() == io::ErrorKind::NotFound => AgentState::default(),
            Err(error) => {
                warn!(%error, path = %path.display(), "could not read agent state; starting with empty state");
                AgentState::default()
            }
        };
        Self {
            path,
            state: Arc::new(Mutex::new(state)),
        }
    }

    pub fn snapshot(&self) -> AgentState {
        self.state
            .lock()
            .expect("agent state mutex poisoned")
            .clone()
    }

    pub fn set_current(
        &self,
        applied: AppliedState,
        previous_successful_config: Option<PathBuf>,
        previous_successful: Option<AppliedState>,
    ) {
        let mut state = self.state.lock().expect("agent state mutex poisoned");
        state.current = applied;
        state.previous_successful_config = previous_successful_config;
        state.previous_successful = previous_successful;
        let current_generation = state.current.generation;
        state
            .failures
            .retain(|entry| entry.generation >= current_generation);
        drop(state);
        self.persist();
    }

    pub fn record_failure(&self, generation: u64, content_hash: &str, error_code: &str) {
        let mut state = self.state.lock().expect("agent state mutex poisoned");
        let current_generation = state.current.generation;
        state.failures.retain(|entry| {
            entry.generation >= current_generation
                && !(entry.generation == generation && entry.content_hash == content_hash)
        });
        state.failures.push(FailureRecord {
            generation,
            content_hash: content_hash.into(),
            error_code: error_code.into(),
        });
        if state.failures.len() > MAX_FAILURES {
            let remove = state.failures.len() - MAX_FAILURES;
            state.failures.drain(..remove);
        }
        drop(state);
        self.persist();
    }

    pub fn failure_code(&self, generation: u64, content_hash: &str) -> Option<String> {
        self.state
            .lock()
            .expect("agent state mutex poisoned")
            .failures
            .iter()
            .find(|entry| entry.generation == generation && entry.content_hash == content_hash)
            .map(|entry| entry.error_code.clone())
    }

    pub fn contains_terminal(&self, generation: u64, content_hash: &str) -> bool {
        self.state
            .lock()
            .expect("agent state mutex poisoned")
            .results
            .iter()
            .filter(|result| {
                ReportApplyResultRequest::decode(result.report.as_slice())
                    .is_ok_and(|report| report.phase != "rejected")
            })
            .any(|result| result.generation == generation && result.content_hash == content_hash)
    }

    pub fn contains_result(&self, generation: u64, content_hash: &str, error_code: &str) -> bool {
        self.state
            .lock()
            .expect("agent state mutex poisoned")
            .results
            .iter()
            .any(|result| {
                result.generation == generation
                    && result.content_hash == content_hash
                    && result.error_code == error_code
            })
    }

    pub fn record_result_for(
        &self,
        report: &ReportApplyResultRequest,
        content_hash: &str,
        confirmed: bool,
    ) {
        let mut state = self.state.lock().expect("agent state mutex poisoned");
        let generation = report.generation.parse().unwrap_or_default();
        let error_code = report.error_code.clone();
        if let Some(entry) = state.results.iter_mut().find(|entry| {
            entry.generation == generation
                && entry.content_hash == content_hash
                && entry.error_code == error_code
        }) {
            entry.report = report.encode_to_vec();
            entry.confirmed |= confirmed;
        } else {
            state.results.push(TerminalResult {
                generation,
                content_hash: content_hash.into(),
                error_code,
                report: report.encode_to_vec(),
                confirmed,
            });
        }
        if state.results.len() > MAX_RESULTS {
            let remove = state.results.len() - MAX_RESULTS;
            state.results.drain(..remove);
        }
        drop(state);
        self.persist();
    }

    pub fn pending_results(&self) -> Vec<(TerminalResult, ReportApplyResultRequest)> {
        self.state
            .lock()
            .expect("agent state mutex poisoned")
            .results
            .iter()
            .filter(|result| !result.confirmed)
            .filter_map(|result| {
                ReportApplyResultRequest::decode(result.report.as_slice())
                    .ok()
                    .map(|report| (result.clone(), report))
            })
            .collect()
    }

    pub fn confirm_result(&self, generation: u64, content_hash: &str, error_code: &str) {
        let mut state = self.state.lock().expect("agent state mutex poisoned");
        if let Some(result) = state.results.iter_mut().find(|result| {
            result.generation == generation
                && result.content_hash == content_hash
                && result.error_code == error_code
        }) {
            result.confirmed = true;
        }
        drop(state);
        self.persist();
    }

    fn persist(&self) {
        let state = self.state.lock().expect("agent state mutex poisoned");
        if let Err(error) = atomic_write(&self.path, &state) {
            warn!(%error, path = %self.path.display(), "could not persist agent state");
        }
    }
}

#[derive(Clone)]
pub struct ReconcileState {
    store: StateStore,
}

impl ReconcileState {
    pub fn new(store: StateStore) -> Self {
        Self { store }
    }

    pub fn has_terminal(&self, generation: u64, hash: &str) -> bool {
        self.store.contains_terminal(generation, hash)
    }

    pub fn has_report(&self, generation: u64, hash: &str, error_code: &str) -> bool {
        self.store.contains_result(generation, hash, error_code)
    }

    pub fn pending(&self) -> Vec<(TerminalResult, ReportApplyResultRequest)> {
        self.store.pending_results()
    }

    pub fn record(&self, report: &ReportApplyResultRequest, hash: &str, confirmed: bool) {
        self.store.record_result_for(report, hash, confirmed);
    }

    pub fn confirm(&self, result: &TerminalResult) {
        self.store
            .confirm_result(result.generation, &result.content_hash, &result.error_code);
    }
}

impl Default for ReconcileState {
    fn default() -> Self {
        let path = std::env::temp_dir().join(format!(
            "cyberboard-agent-test-state-{}-{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        Self::new(StateStore::load(path))
    }
}

fn atomic_write(path: &Path, state: &AgentState) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = PathBuf::from(format!("{}.tmp-{nonce}", path.display()));
    let bytes = serde_json::to_vec(state).map_err(io::Error::other)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_applied_state_is_loaded_without_resetting_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, br#"{"generation":7,"content_hash":"saved-hash"}"#).unwrap();
        let store = StateStore::load(&path);
        assert_eq!(store.snapshot().current.generation, 7);
        assert_eq!(store.snapshot().current.content_hash, "saved-hash");
    }

    #[test]
    fn failure_records_and_result_acknowledgements_survive_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::load(&path);
        store.record_failure(4, "bad-hash", "core_check_failed");
        let pending = ReportApplyResultRequest {
            generation: "4".into(),
            applied_hash: "old-hash".into(),
            phase: "failed".into(),
            error_code: "core_check_failed".into(),
            ..Default::default()
        };
        let confirmed = ReportApplyResultRequest {
            generation: "3".into(),
            applied_hash: "older-hash".into(),
            phase: "applied".into(),
            ..Default::default()
        };
        store.record_result_for(&confirmed, "confirmed-hash", true);
        store.record_result_for(&pending, "bad-hash", false);

        let reloaded = StateStore::load(&path);
        assert_eq!(
            reloaded.failure_code(4, "bad-hash").as_deref(),
            Some("core_check_failed")
        );
        let pending_after_restart = reloaded.pending_results();
        assert_eq!(pending_after_restart.len(), 1);
        assert_eq!(pending_after_restart[0].0.generation, 4);
        assert_eq!(pending_after_restart[0].1.error_code, "core_check_failed");
        reloaded.confirm_result(4, "bad-hash", "core_check_failed");
        assert!(StateStore::load(&path).pending_results().is_empty());
    }

    #[test]
    fn newer_applied_generation_prunes_older_failures() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::load(dir.path().join("state.json"));
        store.record_failure(2, "old", "failed");
        store.set_current(
            AppliedState {
                generation: 3,
                content_hash: "new".into(),
            },
            None,
            None,
        );
        assert!(store.failure_code(2, "old").is_none());
    }

    #[test]
    fn corrupt_state_loads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, b"not json").unwrap();
        assert_eq!(StateStore::load(path).snapshot(), AgentState::default());
    }
}
