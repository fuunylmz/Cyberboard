use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub node_id: Uuid,
    pub public_key: String,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
}

impl AgentIdentity {
    pub fn load(path: impl AsRef<Path>) -> io::Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)?;
        let identity = serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid agent identity: {error}"),
            )
        })?;
        Ok(Some(identity))
    }

    pub fn persist(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            let parent_missing = !parent.exists();
            fs::create_dir_all(parent)?;
            if parent_missing {
                set_private_mode(parent, true)?;
            }
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = PathBuf::from(format!("{}.tmp-{}", path.display(), nonce));
        let data = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        set_private_mode(&temporary, false)?;
        use std::io::Write;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_mode(path: &Path, directory: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path, _directory: bool) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AgentIdentity;
    use std::{env, fs};
    use uuid::Uuid;

    #[test]
    fn identity_round_trips_through_private_atomic_file() {
        let path = env::temp_dir().join(format!(
            "cyberboard-agent-identity-{}.json",
            std::process::id()
        ));
        let identity = AgentIdentity {
            agent_id: "agent-test".to_owned(),
            node_id: Uuid::from_u128(7),
            public_key: "public-key".to_owned(),
            ca_cert_path: Some("ca.pem".to_owned()),
            client_cert_path: Some("client.pem".to_owned()),
            client_key_path: Some("client.key".to_owned()),
        };
        identity.persist(&path).unwrap();
        assert_eq!(AgentIdentity::load(&path).unwrap(), Some(identity));
        let _ = fs::remove_file(path);
    }
}
