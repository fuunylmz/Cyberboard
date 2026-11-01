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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, Command},
    time::timeout,
};
use tracing::{debug, warn};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppliedState {
    pub generation: u64,
    pub content_hash: String,
}

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
    core_state: &'static str,
}

impl CoreSupervisor {
    pub async fn new(
        binary: impl Into<PathBuf>,
        config: impl Into<PathBuf>,
        grace: Duration,
    ) -> Self {
        Self {
            binary: binary.into(),
            config: config.into(),
            grace,
            child: None,
            state: AppliedState::default(),
            core_state: "not_configured",
        }
    }

    pub async fn initialize(&mut self) -> io::Result<()> {
        ensure_parent(&self.config)?;
        let state_path = self.state_path();
        let restored = if self.config.exists() && state_path.exists() {
            let state: AppliedState = serde_json::from_slice(&fs::read(&state_path)?)?;
            if file_hash(&self.config)? == state.content_hash {
                self.state = state;
                true
            } else {
                false
            }
        } else {
            false
        };
        if restored {
            self.start().await?;
            if !self.health_check().await {
                warn!("persisted core config failed startup health check");
            }
        } else if self.config.exists() || state_path.exists() {
            warn!(config = %self.config.display(), "local config/state mismatch; treating applied generation as empty");
            self.state = AppliedState::default();
        }
        Ok(())
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
    pub fn state_path(&self) -> PathBuf {
        self.config.with_extension("state")
    }
    pub fn previous_path(&self) -> PathBuf {
        self.config.with_extension("previous")
    }

    pub async fn check_version(&self) -> Option<String> {
        let output = timeout(
            Duration::from_secs(3),
            Command::new(&self.binary)
                .arg("version")
                .stdin(Stdio::null())
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
                .status(),
        )
        .await;
        if !matches!(checked, Ok(Ok(status)) if status.success()) {
            let _ = fs::remove_file(&temp);
            return fail("core_check_failed", "core config check failed", old_state);
        }
        let previous = self.previous_path();
        if self.config.exists() {
            if let Err(error) = copy_private_sync(&self.config, &previous) {
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
            self.state = AppliedState {
                generation,
                content_hash: content_hash.into(),
            };
            if let Err(error) = self.write_state() {
                return fail("install_failed", &error.to_string(), old_state);
            }
            return ApplyOutcome {
                phase: "applied",
                error_code: String::new(),
                error_message: String::new(),
                state: self.state.clone(),
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
            return fail(
                "rollback_failed",
                "new config unhealthy and previous config could not be restored",
                old_state,
            );
        }
        let _ = fs::remove_file(&self.config);
        let _ = self.stop().await;
        fail(
            "health_check_failed",
            "new config unhealthy and no previous config exists",
            old_state,
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

    pub async fn restart(&mut self) -> io::Result<bool> {
        if self.config.exists() && self.state.generation > 0 {
            self.start().await?;
            return Ok(self.health_check().await);
        }
        Ok(false)
    }

    pub async fn shutdown(&mut self) {
        let _ = self.stop().await;
    }

    async fn start(&mut self) -> io::Result<()> {
        if self.child.is_some() {
            return Ok(());
        }
        self.core_state = "starting";
        let mut child = Command::new(&self.binary)
            .arg("run")
            .arg("-c")
            .arg(&self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
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

    fn write_state(&self) -> io::Result<()> {
        let data = serde_json::to_vec(&self.state).map_err(io::Error::other)?;
        atomic_private_write(&self.state_path(), &data)
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
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

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
        let persisted: AppliedState =
            serde_json::from_slice(&fs::read(supervisor.state_path()).unwrap()).unwrap();
        assert_eq!(
            persisted,
            AppliedState {
                generation: 2,
                content_hash: hash(second)
            }
        );
        supervisor.shutdown().await;
    }

    #[tokio::test]
    async fn unhealthy_reload_restores_previous_config_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(80)).await;
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
    }

    #[tokio::test]
    async fn unhealthy_first_config_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(40)).await;
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
    async fn check_failure_does_not_replace_config_or_state() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sing-box.json");
        let mut supervisor =
            CoreSupervisor::new(fake_core(dir.path()), &config, Duration::from_millis(20)).await;
        supervisor.initialize().await.unwrap();
        let rejected = supervisor
            .apply(b"fail_check", 1, &hash(b"fail_check"))
            .await;
        assert_eq!(rejected.phase, "failed");
        assert_eq!(rejected.error_code, "core_check_failed");
        assert!(!config.exists());
        assert_eq!(supervisor.state(), &AppliedState::default());
        supervisor.shutdown().await;
    }
}
