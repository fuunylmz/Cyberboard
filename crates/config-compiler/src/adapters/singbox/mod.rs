//! sing-box configuration model and adapter.
//!
//! The protocol-specific fields are represented as JSON values so the compiler
//! can retain sing-box's evolving protocol schema while keeping the document
//! envelope and common sections strongly structured and serializable.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{fs, process::Command};
use uuid::Uuid;

use crate::{CompileError, ConfigProfile};

/// Top-level sing-box server configuration emitted by this crate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SingBoxConfig {
    /// Logging settings.
    pub log: LogConfig,
    /// Protocol listeners.
    pub inbounds: Vec<Value>,
    /// Egresses referenced by the route.
    pub outbounds: Vec<Value>,
    /// Routing policy.
    pub route: Value,
    /// Optional feature configuration, including Cyberboard's V2Ray stats API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

/// Standard sing-box logging options.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogConfig {
    /// sing-box log level (`trace`, `debug`, `info`, `warn`, or `error`).
    pub level: String,
    /// Include timestamps in log messages.
    #[serde(default = "default_timestamp")]
    pub timestamp: bool,
}

fn default_timestamp() -> bool {
    true
}

/// Converts the shared profile representation into a sing-box server config.
#[derive(Clone, Copy, Debug, Default)]
pub struct SingBoxAdapter;

impl SingBoxAdapter {
    /// Validate and render a profile to a serializable sing-box configuration.
    pub fn render(&self, profile: &ConfigProfile) -> Result<SingBoxConfig, CompileError> {
        profile.validate()?;
        let rendered = profile.render_sing_box_value()?;
        serde_json::from_value(rendered).map_err(|_| CompileError::InvalidRenderedConfig)
    }

    /// Run `sing-box check -c` against this profile and retain command errors.
    pub fn check_with_binary(
        &self,
        profile: &ConfigProfile,
        binary: impl AsRef<std::path::Path>,
    ) -> Result<(), CompileError> {
        let config = self.render_json(profile)?;
        let path = std::env::temp_dir().join(format!("cyberboard-check-{}.json", Uuid::new_v4()));
        let result = (|| {
            let bytes = serde_json::to_vec(&config)
                .map_err(|error| CompileError::SingBoxCheckFailed(error.to_string()))?;
            fs::write(&path, bytes)
                .map_err(|error| CompileError::SingBoxCheckFailed(error.to_string()))?;
            let output = Command::new(binary.as_ref())
                .arg("check")
                .arg("-c")
                .arg(&path)
                .output()
                .map_err(|error| CompileError::SingBoxCheckFailed(error.to_string()))?;
            if output.status.success() {
                Ok(())
            } else {
                Err(CompileError::SingBoxCheckFailed(format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stderr),
                    String::from_utf8_lossy(&output.stdout)
                )))
            }
        })();
        let _ = fs::remove_file(path);
        result
    }

    /// Validate and render a profile as JSON, useful for API payload creation.
    pub fn render_json(&self, profile: &ConfigProfile) -> Result<Value, CompileError> {
        serde_json::to_value(self.render(profile)?).map_err(|_| CompileError::InvalidRenderedConfig)
    }
}

/// Convenience entry point for callers that use the compiler as a function.
pub fn compile_config(profile: &ConfigProfile) -> Result<Value, CompileError> {
    SingBoxAdapter.render_json(profile)
}

/// Build a clean TLS object without optional null-valued properties.
pub(crate) fn tls_value(
    server_name: &Option<String>,
    certificate_path: &Option<String>,
    key_path: &Option<String>,
) -> Value {
    let mut tls = Map::new();
    tls.insert("enabled".to_owned(), json!(true));
    if let Some(server_name) = server_name {
        tls.insert("server_name".to_owned(), json!(server_name));
    }
    if let Some(certificate_path) = certificate_path {
        tls.insert("certificate_path".to_owned(), json!(certificate_path));
    }
    if let Some(key_path) = key_path {
        tls.insert("key_path".to_owned(), json!(key_path));
    }
    Value::Object(tls)
}
