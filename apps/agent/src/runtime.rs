//! Local core runtime boundary.
//!
//! The runtime accepts already-authenticated config bytes and only invokes the
//! configured core binary with fixed arguments. It never evaluates a shell
//! command received from the control plane.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("compare-and-swap generation mismatch")]
    GenerationMismatch,
    #[error("cannot write temporary config: {0}")]
    Io(#[from] std::io::Error),
    #[error("core config check failed with status {0}")]
    CheckFailed(i32),
    #[error("runtime state is invalid: {0}")]
    InvalidState(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppliedState {
    pub generation: u64,
    pub content_hash: String,
}

pub struct CoreRuntime {
    binary_path: PathBuf,
    config_path: PathBuf,
}

impl CoreRuntime {
    pub fn new(binary_path: impl Into<PathBuf>, config_path: impl Into<PathBuf>) -> Self {
        Self {
            binary_path: binary_path.into(),
            config_path: config_path.into(),
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn apply(
        &self,
        config: &[u8],
        expected_generation: u64,
        current_generation: u64,
    ) -> Result<(), RuntimeError> {
        if expected_generation != current_generation {
            return Err(RuntimeError::GenerationMismatch);
        }
        let temporary_path = self.temporary_path();
        fs::write(&temporary_path, config)?;
        let result = Command::new(&self.binary_path)
            .arg("check")
            .arg("-c")
            .arg(&temporary_path)
            .status()?;
        if !result.success() {
            let _ = fs::remove_file(&temporary_path);
            return Err(RuntimeError::CheckFailed(result.code().unwrap_or(-1)));
        }
        let backup_path = self.config_path.with_extension("previous");
        if self.config_path.exists() {
            fs::copy(&self.config_path, &backup_path)?;
        }
        if let Err(error) = fs::rename(&temporary_path, &self.config_path) {
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
        Ok(())
    }

    pub fn current_state(&self) -> Result<AppliedState, RuntimeError> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(AppliedState::default());
        }
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    pub fn record_state(&self, state: &AppliedState) -> Result<(), RuntimeError> {
        ensure_parent(&self.state_path())?;
        let temporary_path = self.state_path().with_extension(format!(
            "state-tmp-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::write(&temporary_path, serde_json::to_vec(state)?)?;
        if let Err(error) = fs::rename(&temporary_path, self.state_path()) {
            let _ = fs::remove_file(&temporary_path);
            return Err(error.into());
        }
        Ok(())
    }

    pub fn rollback(&self) -> Result<(), RuntimeError> {
        let backup_path = self.config_path.with_extension("previous");
        if backup_path.exists() {
            fs::copy(backup_path, &self.config_path)?;
        }
        Ok(())
    }

    fn temporary_path(&self) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.config_path.with_extension(format!("tmp-{nonce}"))
    }

    fn state_path(&self) -> PathBuf {
        self.config_path.with_extension("state")
    }
}

pub fn ensure_parent(path: &Path) -> Result<(), RuntimeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AppliedState, CoreRuntime, RuntimeError, ensure_parent};
    use std::{env, fs};

    #[test]
    fn rejects_stale_generation_before_running_binary() {
        let path = env::temp_dir().join("cyberboard-runtime-test.json");
        let runtime = CoreRuntime::new("/usr/bin/true", &path);
        assert!(matches!(
            runtime.apply(b"{}", 2, 1),
            Err(RuntimeError::GenerationMismatch)
        ));
    }

    #[test]
    fn checks_and_atomically_installs_config_with_injected_binary() {
        let path = env::temp_dir().join(format!("cyberboard-runtime-{}.json", std::process::id()));
        ensure_parent(&path).unwrap();
        let runtime = CoreRuntime::new("/usr/bin/true", &path);
        runtime.apply(b"{}", 1, 1).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persists_applied_generation_and_hash_atomically() {
        let path = env::temp_dir().join(format!(
            "cyberboard-runtime-state-{}.json",
            std::process::id()
        ));
        let runtime = CoreRuntime::new("/usr/bin/true", &path);
        runtime
            .record_state(&AppliedState {
                generation: 7,
                content_hash: "abc".to_owned(),
            })
            .unwrap();
        assert_eq!(
            runtime.current_state().unwrap(),
            AppliedState {
                generation: 7,
                content_hash: "abc".to_owned(),
            }
        );
        let _ = fs::remove_file(path.with_extension("state"));
    }

    #[test]
    fn missing_state_starts_at_generation_zero() {
        let path = env::temp_dir().join(format!(
            "cyberboard-runtime-missing-state-{}.json",
            std::process::id()
        ));
        let runtime = CoreRuntime::new("/usr/bin/true", &path);
        assert_eq!(runtime.current_state().unwrap(), AppliedState::default());
    }
}
