//! Direct lifecycle management for a sing-box child process.
//!
//! Configuration is checked before start/reload. sing-box does not expose a
//! reliable reload acknowledgement, so reload health is determined by liveness;
//! a dead or un-signallable process is restarted with the requested config.

use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{
    process::{Child, Command},
    time::{sleep, timeout},
};
use tracing::{debug, warn};

/// Process health as observed by the agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthStatus {
    /// A child process exists and has not exited.
    Healthy,
    /// No child process is running.
    Stopped,
    /// A child exited unexpectedly or its state cannot be determined.
    Unhealthy,
}

/// Lifecycle operations supported by a local proxy core runtime.
pub trait CoreRuntime {
    /// Validate and start the core with `config_path`.
    async fn start(&mut self, config_path: &Path) -> io::Result<()>;
    /// Apply a config by signaling the live core, restarting if needed.
    async fn reload(&mut self, config_path: &Path) -> io::Result<()>;
    /// Gracefully stop the core, escalating to SIGKILL after 30 seconds.
    async fn stop(&mut self) -> io::Result<()>;
    /// Report whether the managed process is alive.
    async fn health_check(&self) -> io::Result<HealthStatus>;
    /// Return the managed process ID, if running.
    fn pid(&self) -> Option<u32>;
}

/// A sing-box process and the binary used to manage it.
pub struct SingBoxRuntime {
    binary: PathBuf,
    child: Option<Child>,
}

impl SingBoxRuntime {
    /// Create a runtime for `binary` (for example `/usr/local/bin/sing-box`).
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            child: None,
        }
    }

    async fn check_config(&self, path: &Path) -> io::Result<()> {
        let status = Command::new(&self.binary)
            .arg("check")
            .arg("-c")
            .arg(path)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .status()
            .await?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "sing-box config check failed with {status}"
            )))
        }
    }

    async fn spawn(&mut self, config_path: &Path) -> io::Result<()> {
        let mut child = Command::new(&self.binary)
            .arg("run")
            .arg("-c")
            .arg(config_path)
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
        debug!(pid = self.pid(), "started sing-box process");
        Ok(())
    }
}

impl CoreRuntime for SingBoxRuntime {
    async fn start(&mut self, config_path: &Path) -> io::Result<()> {
        self.check_config(config_path).await?;
        if matches!(self.health_check().await?, HealthStatus::Healthy) {
            return Ok(());
        }
        self.child = None;
        self.spawn(config_path).await
    }

    async fn reload(&mut self, config_path: &Path) -> io::Result<()> {
        self.check_config(config_path).await?;
        #[cfg(unix)]
        {
            if let Some(child) = self.child.as_mut() {
                if matches!(child.try_wait(), Ok(None)) {
                    if let Some(pid) = child.id() {
                        // SAFETY: this PID belongs to the live child managed here.
                        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGUSR1) };
                        if result == 0 {
                            sleep(Duration::from_millis(100)).await;
                            if matches!(self.health_check().await?, HealthStatus::Healthy) {
                                return Ok(());
                            }
                        } else {
                            warn!(pid, error = %io::Error::last_os_error(), "could not signal sing-box; restarting");
                        }
                    }
                }
            }
        }
        self.stop().await?;
        self.spawn(config_path).await
    }

    async fn stop(&mut self) -> io::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Some(pid) = child.id() {
            #[cfg(unix)]
            {
                // SAFETY: this PID belongs to the child being waited on below.
                if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        warn!(%error, pid, "SIGTERM failed");
                    }
                }
            }
        }
        if timeout(Duration::from_secs(30), child.wait())
            .await
            .is_err()
        {
            warn!(
                pid = child.id(),
                "sing-box did not stop in 30 seconds; sending SIGKILL"
            );
            child.kill().await?;
            child.wait().await?;
        }
        Ok(())
    }

    async fn health_check(&self) -> io::Result<HealthStatus> {
        let Some(child) = self.child.as_ref() else {
            return Ok(HealthStatus::Stopped);
        };
        match child.id() {
            None => Ok(HealthStatus::Unhealthy),
            Some(_) => {
                // Child::try_wait requires mutable access; on Unix kill(pid, 0)
                // provides a non-mutating liveness check for the owned PID.
                #[cfg(unix)]
                {
                    // SAFETY: signal 0 performs no action; it only checks the PID.
                    let result = unsafe { libc::kill(child.id().unwrap() as libc::pid_t, 0) };
                    if result == 0 {
                        Ok(HealthStatus::Healthy)
                    } else {
                        Ok(HealthStatus::Unhealthy)
                    }
                }
                #[cfg(not(unix))]
                {
                    Ok(HealthStatus::Healthy)
                }
            }
        }
    }

    fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(Child::id)
    }
}

async fn log_lines<R: tokio::io::AsyncRead + Unpin>(reader: R, is_stderr: bool) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if is_stderr {
            tracing::debug!(target: "sing_box", stream = "stderr", message = %line);
        } else {
            tracing::debug!(target: "sing_box", stream = "stdout", message = %line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreRuntime, HealthStatus, SingBoxRuntime};
    use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

    fn fake_binary(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("sing-box-test");
        fs::write(&path, "#!/bin/sh\ncase $1 in\ncheck) grep -q invalid \"$3\" && exit 1; exit 0;;\nrun) trap 'exit 0' USR1 TERM; while :; do sleep 0.05; done;;\nesac\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn starts_and_reports_pid_then_stops() {
        let dir = tempfile::tempdir().unwrap();
        let binary = fake_binary(dir.path());
        let config = dir.path().join("config.json");
        fs::write(&config, "{}").unwrap();
        let mut runtime = SingBoxRuntime::new(binary);
        runtime.start(&config).await.unwrap();
        assert!(runtime.pid().is_some());
        assert_eq!(runtime.health_check().await.unwrap(), HealthStatus::Healthy);
        runtime.stop().await.unwrap();
        assert_eq!(runtime.health_check().await.unwrap(), HealthStatus::Stopped);
    }

    #[tokio::test]
    async fn rejects_invalid_config_and_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let binary = fake_binary(dir.path());
        let config = dir.path().join("config.json");
        fs::write(&config, "invalid").unwrap();
        let mut runtime = SingBoxRuntime::new(binary);
        assert!(runtime.start(&config).await.is_err());
        fs::write(&config, "{}").unwrap();
        let mut missing = SingBoxRuntime::new(dir.path().join("missing"));
        assert!(missing.start(&config).await.is_err());
    }

    #[tokio::test]
    async fn reload_signals_running_process() {
        let dir = tempfile::tempdir().unwrap();
        let binary = fake_binary(dir.path());
        let config = dir.path().join("config.json");
        fs::write(&config, "{}").unwrap();
        let mut runtime = SingBoxRuntime::new(binary);
        runtime.start(&config).await.unwrap();
        let pid = runtime.pid();
        runtime.reload(&config).await.unwrap();
        assert_eq!(runtime.pid(), pid);
        runtime.stop().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
