//! Supervision boundary for the local sing-box process.
//!
//! Liveness after the grace period is the health signal; sing-box keeps its old
//! instance when a SIGHUP reload fails internally, so the pre-install `check` is
//! what catches invalid configs.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, Command},
    time::timeout,
};
use tracing::{debug, warn};

use crate::state::StateStore;

pub use crate::state::AppliedState;

#[derive(Clone, Debug)]
pub struct ApplyOutcome {
    pub phase: &'static str,
    pub error_code: String,
    pub error_message: String,
    pub state: AppliedState,
}

pub struct CoreSupervisor {
    binary: PathBuf,
    config: PathBuf,
    grace: Duration,
    child: Option<Child>,
    state: AppliedState,
    durable: StateStore,
    core_state: &'static str,
}

impl CoreSupervisor {
    #[cfg(test)]
    pub async fn new(
        binary: impl Into<PathBuf>,
        config: impl Into<PathBuf>,
        grace: Duration,
    ) -> Self {
        let config = config.into();
        let durable = StateStore::load(config.with_extension("state"));
        Self::new_with_state_store(binary, config, grace, durable).await
    }

    pub async fn new_with_state_store(
        binary: impl Into<PathBuf>,
        config: impl Into<PathBuf>,
        grace: Duration,
        durable: StateStore,
    ) -> Self {
        Self {
            binary: binary.into(),
            config: config.into(),
            grace,
            child: None,
            state: AppliedState::default(),
            durable,
            core_state: "not_configured",
        }
    }

    pub async fn initialize(&mut self) -> io::Result<()> {
        ensure_parent(&self.config)?;
        let persisted = self.durable.snapshot();
        let mut restored = false;
        if persisted.current.generation > 0 {
            if self.config.exists()
                && file_hash(&self.config).is_ok_and(|hash| hash == persisted.current.content_hash)
            {
                self.state = persisted.current.clone();
                restored = true;
            } else if let Some(previous) = persisted.previous_successful_config.as_ref() {
                let recovered = file_hash(previous).ok().and_then(|hash| {
                    if hash == persisted.current.content_hash {
                        Some(persisted.current.clone())
                    } else if persisted
                        .previous_successful
                        .as_ref()
                        .is_some_and(|state| state.content_hash == hash)
                    {
                        persisted.previous_successful.clone()
                    } else {
                        None
                    }
                });
                if let Some(recovered_state) = recovered {
                    copy_private_sync(previous, &self.config)?;
                    self.state = recovered_state;
                    self.durable.set_current(self.state.clone(), None, None);
                    restored = true;
                }
            }
        }
        if restored {
            if let Err(error) = self.start().await {
                self.core_state = "crashed";
                warn!(%error, "could not start sing-box from persisted config; supervision will retry");
            } else if !self.health_check().await {
                warn!("persisted core config failed startup health check");
            }
        } else {
            if self.config.exists() {
                warn!(config = %self.config.display(), "local config does not match persisted applied state; moving it aside");
                let unverified = self.unverified_path();
                if let Err(error) = fs::rename(&self.config, &unverified) {
                    warn!(%error, path = %unverified.display(), "could not move unverified config");
                } else if let Err(error) = set_private(&unverified) {
                    warn!(%error, path = %unverified.display(), "could not restrict unverified config permissions");
                }
            }
            self.state = AppliedState::default();
            self.durable.set_current(self.state.clone(), None, None);
        }
        Ok(())
    }

    pub fn is_known_failure(&self, generation: u64, content_hash: &str) -> Option<String> {
        self.durable.failure_code(generation, content_hash)
    }

    pub fn state(&self) -> &AppliedState {
        &self.state
    }
    pub fn core_state(&self) -> &'static str {
        self.core_state
    }
    pub fn config_path(&self) -> &Path {
        &self.config
    }
    #[cfg(test)]
    pub fn state_path(&self) -> PathBuf {
        self.config.with_extension("state")
    }
    pub fn previous_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.previous", self.config.display()))
    }
    pub fn unverified_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.unverified", self.config.display()))
    }

    pub async fn check_version(&self) -> Option<String> {
        let output = timeout(
            Duration::from_secs(3),
            Command::new(&self.binary)
                .arg("version")
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .ok()?
        .ok()?;
        output
            .status
            .success()
            .then(|| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            })
            .filter(|s| !s.is_empty())
    }

    pub async fn apply(
        &mut self,
        payload: &[u8],
        generation: u64,
        content_hash: &str,
    ) -> ApplyOutcome {
        let outcome = self.apply_inner(payload, generation, content_hash).await;
        if outcome.phase != "applied" {
            self.durable
                .record_failure(generation, content_hash, &outcome.error_code);
        }
        outcome
    }

    async fn apply_inner(
        &mut self,
        payload: &[u8],
        generation: u64,
        content_hash: &str,
    ) -> ApplyOutcome {
        let old_state = self.state.clone();
        let fail = |code: &str, message: &str, state: AppliedState| ApplyOutcome {
            phase: "failed",
            error_code: code.into(),
            error_message: message.chars().take(512).collect(),
            state,
        };
        if ensure_parent(&self.config).is_err() {
            return fail(
                "install_failed",
                "could not create config directory",
                old_state,
            );
        }
        let temp = unique_sibling(&self.config, "tmp");
        if let Err(error) = write_private_sync(&temp, payload) {
            return fail("install_failed", &error.to_string(), old_state);
        }
        let checked = timeout(
            Duration::from_secs(10),
            Command::new(&self.binary)
                .arg("check")
                .arg("-c")
                .arg(&temp)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await;
        if !matches!(checked, Ok(Ok(status)) if status.success()) {
            let _ = fs::remove_file(&temp);
            return fail("core_check_failed", "core config check failed", old_state);
        }
        let previous = self.previous_path();
        if self.state.generation > 0 && self.config.exists() {
            if let Err(error) = copy_private_sync(&self.config, &previous) {
                let _ = fs::remove_file(&temp);
                return fail("install_failed", &error.to_string(), old_state);
            }
        } else if previous.exists() {
            if let Err(error) = fs::remove_file(&previous) {
                let _ = fs::remove_file(&temp);
                return fail("install_failed", &error.to_string(), old_state);
            }
        }
        if let Err(error) = fs::rename(&temp, &self.config) {
            let _ = fs::remove_file(&temp);
            return fail("install_failed", &error.to_string(), old_state);
        }
        if let Some(parent) = self.config.parent() {
            if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
                return fail("install_failed", &error.to_string(), old_state);
            }
        }
        if self.child.is_some() {
            self.reload_or_restart().await;
        } else {
            let _ = self.start().await;
        }
        if self.health_check().await {
            let new_state = AppliedState {
                generation,
                content_hash: content_hash.into(),
            };
            let previous_state = (old_state.generation > 0).then(|| old_state.clone());
            let previous_path = previous_state.as_ref().map(|_| self.previous_path());
            self.durable
                .set_current(new_state.clone(), previous_path, previous_state);
            self.state = new_state.clone();
            return ApplyOutcome {
                phase: "applied",
                error_code: String::new(),
                error_message: String::new(),
                state: new_state,
            };
        }
        if previous.exists() {
            let restore_tmp = unique_sibling(&self.config, "restore");
            if copy_private_sync(&previous, &restore_tmp).is_ok()
                && fs::rename(&restore_tmp, &self.config).is_ok()
            {
                if let Some(parent) = self.config.parent() {
                    let _ = File::open(parent).and_then(|directory| directory.sync_all());
                }
                self.reload_or_restart().await;
                if self.health_check().await {
                    self.state = old_state.clone();
                    self.durable.set_current(
                        old_state.clone(),
                        Some(previous.clone()),
                        Some(old_state.clone()),
                    );
                    return ApplyOutcome {
                        phase: "rolled_back",
                        error_code: "health_check_failed".into(),
                        error_message: "new config failed health check; previous config restored"
                            .into(),
                        state: old_state,
                    };
                }
            }
            let _ = fs::remove_file(&self.config);
            let _ = self.stop().await;
            self.state = AppliedState::default();
            self.durable.set_current(self.state.clone(), None, None);
            return fail(
                "rollback_failed",
                "new config unhealthy and previous config could not be restored",
                self.state.clone(),
            );
        }
        let _ = fs::remove_file(&self.config);
        let _ = self.stop().await;
        self.state = AppliedState::default();
        self.durable.set_current(self.state.clone(), None, None);
        fail(
            "health_check_failed",
            "new config unhealthy and no previous config exists",
            self.state.clone(),
        )
    }

    pub async fn supervise_once(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.child = None;
                self.core_state = "crashed";
                warn!("sing-box exited unexpectedly");
            }
            Ok(None) => {}
            Err(error) => warn!(%error, "could not inspect sing-box process"),
        }
    }

    pub async fn restart(&mut self) -> io::Result<()> {
        if self.config.exists() && self.state.generation > 0 {
            self.start().await?;
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) {
        let _ = self.stop().await;
    }

    async fn start(&mut self) -> io::Result<()> {
        if self.child.is_some() {
            return Ok(());
        }
        self.core_state = "starting";
        let mut child = match Command::new(&self.binary)
            .arg("run")
            .arg("-c")
            .arg(&self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                self.core_state = "crashed";
                return Err(error);
            }
        };
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(log_lines(stdout, false));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(log_lines(stderr, true));
        }
        self.child = Some(child);
        self.core_state = "running";
        Ok(())
    }

    async fn health_check(&mut self) -> bool {
        tokio::time::sleep(self.grace).await;
        let alive = match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        };
        self.core_state = if alive { "running" } else { "crashed" };
        alive
    }

    async fn reload_or_restart(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if matches!(child.try_wait(), Ok(Some(_))) {
                self.child = None;
            }
        }
        #[cfg(unix)]
        if let Some(child) = self.child.as_mut() {
            if let Some(pid) = child.id() {
                self.core_state = "reloading";
                // SAFETY: pid is the live child process id owned by this supervisor.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGHUP);
                }
                self.core_state = "running";
                return;
            }
        }
        let _ = self.stop().await;
        let _ = self.start().await;
    }

    async fn stop(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.child.take() {
            if let Some(pid) = child.id() {
                #[cfg(unix)]
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
            }
            if timeout(Duration::from_secs(10), child.wait())
                .await
                .is_err()
            {
                child.kill().await?;
            }
        }
        self.core_state = "stopped";
        Ok(())
    }
}

async fn log_lines<R: tokio::io::AsyncRead + Unpin>(reader: R, is_stderr: bool) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if is_stderr {
            debug!(target: "sing_box", stream = "stderr", message = %line);
        } else {
            debug!(target: "sing_box", stream = "stdout", message = %line);
        }
    }
}

fn file_hash(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn unique_sibling(path: &Path, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("{suffix}-{nonce}"))
}

fn write_private_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    set_private(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn copy_private_sync(source: &Path, target: &Path) -> io::Result<()> {
    let bytes = fs::read(source)?;
    atomic_private_write(target, &bytes)
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    ensure_parent(path)?;
    let temp = unique_sibling(path, "tmp");
    write_private_sync(&temp, bytes)?;
    fs::rename(&temp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_private(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub async fn binary_has_v2ray_api(binary: &Path) -> bool {
    let output = timeout(
        Duration::from_secs(3),
        Command::new(binary)
            .arg("version")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await;
    let Ok(Ok(output)) = output else {
        return false;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains("with_v2ray_api")
}

pub struct ProcessMetrics {
    pub memory_bytes: u64,
    pub cpu_percent: f64,
}

pub async fn process_metrics(pids: &[u32]) -> Option<ProcessMetrics> {
    let pid_list = pids
        .iter()
        .copied()
        .filter(|pid| *pid > 0)
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if pid_list.is_empty() {
        return None;
    }
    let output = timeout(
        Duration::from_secs(2),
        Command::new("ps")
            .args(["-o", "rss=", "-o", "%cpu=", "-p", &pid_list])
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut memory_kib = 0_u64;
    let mut cpu_percent = 0.0_f64;
    let mut found = false;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let (Some(memory), Some(cpu)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(memory), Ok(cpu)) = (memory.parse::<u64>(), cpu.parse::<f64>()) else {
            continue;
        };
        if !cpu.is_finite() || cpu < 0.0 {
            continue;
        }
        memory_kib = memory_kib.saturating_add(memory);
        cpu_percent += cpu;
        found = true;
    }
    found.then_some(ProcessMetrics {
        memory_bytes: memory_kib.saturating_mul(1024),
        cpu_percent,
    })
}

impl CoreSupervisor {
    pub fn process_id(&self) -> Option<u32> {
        self.child.as_ref().and_then(|child| child.id())
    }
}

pub fn disk_free_bytes(path: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return 0;
        };
        // SAFETY: statvfs receives a valid C path and initialized output storage.
        unsafe {
            let mut stats = std::mem::zeroed::<libc::statvfs>();
            if libc::statvfs(path.as_ptr(), &mut stats) == 0 {
                stats.f_bavail as u64 * stats.f_frsize as u64
            } else {
                0
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{AppliedState, CoreSupervisor};
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

    fn hash(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn fake_core(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("fake-sing-box");
        fs::write(&path, "#!/bin/sh\ncase \"$1\" in\nversion) echo 'sing-box version test' ;;\ncheck) grep -q fail_check \"$3\" && exit 1; exit 0 ;;\nrun) trap 'echo hup >> \"$3.hup\"; grep -q crash_on_reload \"$3\" && exit 1' HUP; grep -q crash_on_start \"$3\" && exit 1; while :; do sleep 0.02; done ;;\nesac\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    async fn wait_for(path: &std::path::Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn installs_first_generation_and_reloads_next_generation() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(30)).await;
        supervisor.initialize().await.unwrap();
        let first = b"{\"generation\":1}";
        let outcome = supervisor.apply(first, 1, &hash(first)).await;
        assert_eq!(outcome.phase, "applied");
        assert_eq!(
            outcome.state,
            AppliedState {
                generation: 1,
                content_hash: hash(first)
            }
        );
        assert_eq!(fs::read(&config).unwrap(), first);
        let second = b"{\"generation\":2}";
        let outcome = supervisor.apply(second, 2, &hash(second)).await;
        assert_eq!(outcome.phase, "applied");
        assert_eq!(fs::read(&config).unwrap(), second);
        assert_eq!(fs::read(supervisor.previous_path()).unwrap(), first);
        wait_for(&config.with_extension("json.hup")).await;
        let persisted: crate::state::AgentState =
            serde_json::from_slice(&fs::read(supervisor.state_path()).unwrap()).unwrap();
        assert_eq!(
            persisted.current,
            AppliedState {
                generation: 2,
                content_hash: hash(second)
            }
        );
        supervisor.shutdown().await;
    }

    fn find_sing_box_binary() -> Result<PathBuf, String> {
        if let Some(configured) = std::env::var_os("CYBERBOARD_SING_BOX_BINARY") {
            let binary = PathBuf::from(configured);
            return binary.is_file().then_some(binary.clone()).ok_or_else(|| {
                format!(
                    "CYBERBOARD_SING_BOX_BINARY path does not exist: {}",
                    binary.display()
                )
            });
        }
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|directory| directory.join("sing-box"))
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| "sing-box was not found on PATH".to_owned())
    }

    #[tokio::test]
    async fn real_sing_box_restarts_with_persisted_config() {
        let binary = match find_sing_box_binary() {
            Ok(binary) => binary,
            Err(reason) => {
                eprintln!("skipping real sing-box restart test: {reason}");
                return;
            }
        };
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 18149)) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!(
                    "skipping real sing-box restart test: 127.0.0.1:18149 unavailable: {error}"
                );
                return;
            }
        };
        drop(listener);

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let payload = br#"{"log":{"level":"error"},"inbounds":[{"type":"socks","tag":"local-socks","listen":"127.0.0.1","listen_port":18149}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"#;
        let mut supervisor =
            CoreSupervisor::new(&binary, &config, Duration::from_millis(500)).await;
        supervisor.initialize().await.unwrap();
        assert_eq!(
            supervisor.apply(payload, 1, &hash(payload)).await.phase,
            "applied"
        );
        supervisor.shutdown().await;

        let mut restarted = CoreSupervisor::new(&binary, &config, Duration::from_millis(500)).await;
        restarted.initialize().await.unwrap();
        assert_eq!(restarted.state().generation, 1);
        assert_eq!(restarted.core_state(), "running");
        restarted.shutdown().await;
    }

    #[tokio::test]
    async fn startup_recovers_previous_file_matching_persisted_current_state() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let previous = PathBuf::from(format!("{}.previous", config.display()));
        let binary = fake_core(dir.path());
        let known_good = b"persisted generation seven";
        fs::write(&config, b"uncommitted generation eight").unwrap();
        fs::write(&previous, known_good).unwrap();
        let durable = crate::state::StateStore::load(config.with_extension("state"));
        durable.set_current(
            AppliedState {
                generation: 7,
                content_hash: hash(known_good),
            },
            Some(previous),
            Some(AppliedState {
                generation: 6,
                content_hash: "older-hash".into(),
            }),
        );

        let mut supervisor = CoreSupervisor::new_with_state_store(
            &binary,
            &config,
            Duration::from_millis(20),
            durable,
        )
        .await;
        supervisor.initialize().await.unwrap();
        assert_eq!(fs::read(&config).unwrap(), known_good);
        assert_eq!(supervisor.state().generation, 7);
        assert_eq!(supervisor.core_state(), "running");
        supervisor.shutdown().await;
    }

    #[tokio::test]
    async fn restart_restores_previous_successful_config_when_current_is_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let binary = fake_core(dir.path());
        let first = b"{\"generation\":1}";
        let second = b"{\"generation\":2}";
        let mut supervisor = CoreSupervisor::new(&binary, &config, Duration::from_millis(20)).await;
        supervisor.initialize().await.unwrap();
        assert_eq!(
            supervisor.apply(first, 1, &hash(first)).await.phase,
            "applied"
        );
        assert_eq!(
            supervisor.apply(second, 2, &hash(second)).await.phase,
            "applied"
        );
        supervisor.shutdown().await;

        fs::write(&config, b"unusable interrupted install").unwrap();
        let mut restarted = CoreSupervisor::new(&binary, &config, Duration::from_millis(20)).await;
        restarted.initialize().await.unwrap();
        assert_eq!(fs::read(&config).unwrap(), first);
        assert_eq!(restarted.state().generation, 1);
        assert_eq!(restarted.core_state(), "running");
        restarted.shutdown().await;
    }

    #[tokio::test]
    async fn unhealthy_reload_restores_previous_config_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(350)).await;
        supervisor.initialize().await.unwrap();
        let first = b"{\"generation\":1}";
        assert_eq!(
            supervisor.apply(first, 1, &hash(first)).await.phase,
            "applied"
        );
        let bad = b"crash_on_reload";
        let outcome = supervisor.apply(bad, 2, &hash(bad)).await;
        assert_eq!(outcome.phase, "rolled_back");
        assert_eq!(outcome.error_code, "health_check_failed");
        assert_eq!(fs::read(&config).unwrap(), first);
        assert_eq!(supervisor.state().generation, 1);
        assert_eq!(supervisor.core_state(), "running");
        supervisor.shutdown().await;
        fs::write(&config, b"interrupted invalid config").unwrap();
        let mut restarted =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(20)).await;
        restarted.initialize().await.unwrap();
        assert_eq!(fs::read(&config).unwrap(), first);
        assert_eq!(restarted.state().generation, 1);
        restarted.shutdown().await;
    }

    #[tokio::test]
    async fn unhealthy_first_config_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(350)).await;
        supervisor.initialize().await.unwrap();
        let bad = b"crash_on_start";
        let outcome = supervisor.apply(bad, 1, &hash(bad)).await;
        assert_eq!(outcome.phase, "failed");
        assert_eq!(outcome.error_code, "health_check_failed");
        assert!(!config.exists());
        assert_eq!(supervisor.state(), &AppliedState::default());
        supervisor.shutdown().await;
    }

    #[tokio::test]
    async fn unverified_config_is_quarantined_and_never_becomes_rollback_source() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        fs::write(&config, b"unverified old config").unwrap();
        let previous = PathBuf::from(format!("{}.previous", config.display()));
        fs::write(&previous, b"stale backup").unwrap();
        let durable = crate::state::StateStore::load(config.with_extension("state"));
        durable.set_current(
            AppliedState {
                generation: 8,
                content_hash: "different-current".into(),
            },
            Some(previous),
            Some(AppliedState {
                generation: 7,
                content_hash: "different-previous".into(),
            }),
        );
        durable.record_failure(9, "failed-hash", "core_check_failed");
        durable.record_result_for(
            &cyberboard_agent_protocol::generated::ReportApplyResultRequest {
                generation: "9".into(),
                applied_hash: "old-hash".into(),
                phase: "failed".into(),
                error_code: "core_check_failed".into(),
                ..Default::default()
            },
            "failed-hash",
            false,
        );
        let mut supervisor = CoreSupervisor::new_with_state_store(
            fake_core(dir.path()),
            &config,
            Duration::from_millis(350),
            durable,
        )
        .await;
        supervisor.initialize().await.unwrap();
        assert!(!config.exists());
        assert_eq!(
            fs::read(supervisor.unverified_path()).unwrap(),
            b"unverified old config"
        );
        assert_eq!(
            fs::metadata(supervisor.unverified_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(supervisor.state(), &AppliedState::default());
        let cleared = serde_json::from_slice::<crate::state::AgentState>(
            &fs::read(supervisor.state_path()).unwrap(),
        )
        .unwrap();
        assert_eq!(cleared.current, AppliedState::default());
        assert!(cleared.previous_successful_config.is_none());
        assert!(cleared.previous_successful.is_none());
        assert_eq!(cleared.failures.len(), 1);
        assert_eq!(cleared.results.len(), 1);
        let bad = b"crash_on_start";
        let result = supervisor.apply(bad, 1, &hash(bad)).await;
        assert_eq!(result.phase, "failed");
        assert_eq!(result.state, AppliedState::default());
        assert!(!config.exists());
        assert!(!supervisor.previous_path().exists());
        let persisted: crate::state::AgentState =
            serde_json::from_slice(&fs::read(supervisor.state_path()).unwrap()).unwrap();
        assert_eq!(persisted.current, AppliedState::default());
        supervisor.shutdown().await;
    }

    #[tokio::test]
    async fn corrupt_local_state_and_core_spawn_failure_do_not_abort_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let bytes = b"persisted";
        fs::write(&config, bytes).unwrap();
        fs::write(
            config.with_extension("state"),
            serde_json::to_vec(&AppliedState {
                generation: 7,
                content_hash: hash(bytes),
            })
            .unwrap(),
        )
        .unwrap();
        let mut supervisor = CoreSupervisor::new(
            dir.path().join("missing-core"),
            &config,
            Duration::from_millis(20),
        )
        .await;
        supervisor.initialize().await.unwrap();
        assert_eq!(supervisor.state().generation, 7);
        assert_eq!(supervisor.core_state(), "crashed");
    }

    #[tokio::test]
    async fn state_write_failure_does_not_abort_application() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(20)).await;
        supervisor.initialize().await.unwrap();
        fs::remove_file(supervisor.state_path()).unwrap();
        fs::create_dir(supervisor.state_path()).unwrap();
        let bytes = b"valid config";
        let result = supervisor.apply(bytes, 1, &hash(bytes)).await;
        assert_eq!(result.phase, "applied");
        assert_eq!(supervisor.state().generation, 1);
        assert_eq!(result.state.generation, 1);
        supervisor.shutdown().await;
    }

    #[tokio::test]
    async fn rollback_failure_removes_config_and_resets_persisted_state() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let binary = fake_core(dir.path());
        let mut supervisor =
            CoreSupervisor::new(&binary, &config, Duration::from_millis(350)).await;
        supervisor.initialize().await.unwrap();
        let prior = b"restore_unhealthy";
        assert_eq!(
            supervisor.apply(prior, 1, &hash(prior)).await.phase,
            "applied"
        );
        fs::write(&binary, "#!/bin/sh\ncase \"$1\" in\ncheck) exit 0 ;;\nrun) trap 'grep -q crash_on_reload \"$3\" && exit 1' HUP; grep -q restore_unhealthy \"$3\" && exit 1; while :; do sleep 0.02; done ;;\nesac\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let bad = b"crash_on_reload";
        let outcome = supervisor.apply(bad, 2, &hash(bad)).await;
        assert_eq!(outcome.phase, "failed");
        assert_eq!(outcome.error_code, "rollback_failed");
        assert!(!config.exists());
        assert_eq!(supervisor.state(), &AppliedState::default());
        let persisted: crate::state::AgentState =
            serde_json::from_slice(&fs::read(supervisor.state_path()).unwrap()).unwrap();
        assert_eq!(persisted.current, AppliedState::default());
        supervisor.shutdown().await;
    }

    #[tokio::test]
    async fn check_failure_leaves_verified_running_generation_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(350)).await;
        supervisor.initialize().await.unwrap();
        let first = b"{\"generation\":1}";
        assert_eq!(
            supervisor.apply(first, 1, &hash(first)).await.phase,
            "applied"
        );
        let previous_path = supervisor.previous_path();
        fs::write(&previous_path, b"previous sentinel").unwrap();
        let rejected = supervisor
            .apply(b"fail_check", 2, &hash(b"fail_check"))
            .await;
        assert_eq!(rejected.phase, "failed");
        assert_eq!(rejected.error_code, "core_check_failed");
        assert_eq!(fs::read(&config).unwrap(), first);
        let persisted: crate::state::AgentState =
            serde_json::from_slice(&fs::read(supervisor.state_path()).unwrap()).unwrap();
        assert_eq!(persisted.current.generation, 1);
        assert_eq!(persisted.failures.len(), 1);
        assert_eq!(persisted.failures[0].error_code, "core_check_failed");
        assert_eq!(fs::read(previous_path).unwrap(), b"previous sentinel");
        assert_eq!(supervisor.state().generation, 1);
        supervisor.shutdown().await;
    }
}
