//! Environment-backed service configuration.
//!
//! Secrets are intentionally not logged by the applications. The config structs
//! also avoid deriving `Debug`, so accidental structured logging cannot expose a
//! database URL containing credentials.

use std::{env, net::SocketAddr, num::ParseIntError, str::FromStr};

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid {field}: {source}")]
    InvalidNumber {
        field: &'static str,
        #[source]
        source: ParseIntError,
    },

    #[error("invalid node id: {0}")]
    InvalidNodeId(#[from] uuid::Error),

    #[error("invalid bind address: {0}")]
    InvalidBindAddress(#[from] std::net::AddrParseError),
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn env_u16(name: &'static str, default: u16) -> Result<u16, ConfigError> {
    match optional_env(name) {
        Some(value) => value.parse().map_err(|source| ConfigError::InvalidNumber {
            field: name,
            source,
        }),
        None => Ok(default),
    }
}

fn env_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match optional_env(name) {
        Some(value) => value.parse().map_err(|source| ConfigError::InvalidNumber {
            field: name,
            source,
        }),
        None => Ok(default),
    }
}

fn env_bind_addr() -> String {
    optional_env("CYBERBOARD_BIND_ADDR").unwrap_or_else(|| "0.0.0.0".to_owned())
}

#[derive(Clone)]
pub struct ApiConfig {
    pub bind_addr: String,
    pub port: u16,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub demo_admin_email: String,
    pub demo_admin_password: String,
}

impl ApiConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            bind_addr: env_bind_addr(),
            port: env_u16("CYBERBOARD_API_PORT", 8080)?,
            database_url: optional_env("CYBERBOARD_DATABASE_URL"),
            redis_url: optional_env("CYBERBOARD_REDIS_URL"),
            demo_admin_email: optional_env("CYBERBOARD_DEMO_ADMIN_EMAIL")
                .unwrap_or_else(|| "admin@example.com".to_owned()),
            demo_admin_password: optional_env("CYBERBOARD_DEMO_ADMIN_PASSWORD")
                .unwrap_or_else(|| "password".to_owned()),
        })
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        SocketAddr::from_str(&format!("{}:{}", self.bind_addr, self.port))
            .map_err(ConfigError::InvalidBindAddress)
    }

    pub fn database_configured(&self) -> bool {
        self.database_url.is_some()
    }
}

#[derive(Clone)]
pub struct WorkerConfig {
    pub interval_secs: u64,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
}

impl WorkerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            interval_secs: env_u64("CYBERBOARD_WORKER_INTERVAL_SECS", 30)?.max(1),
            database_url: optional_env("CYBERBOARD_DATABASE_URL"),
            redis_url: optional_env("CYBERBOARD_REDIS_URL"),
        })
    }
}

#[derive(Clone)]
pub struct AgentConfig {
    pub control_plane_url: String,
    pub node_id: Option<Uuid>,
    pub interval_secs: u64,
}

impl AgentConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let node_id = optional_env("CYBERBOARD_NODE_ID")
            .map(|value| Uuid::parse_str(&value))
            .transpose()?;

        Ok(Self {
            control_plane_url: optional_env("CYBERBOARD_CONTROL_PLANE_URL")
                .unwrap_or_else(|| "https://127.0.0.1:8080".to_owned()),
            node_id,
            interval_secs: env_u64("CYBERBOARD_AGENT_INTERVAL_SECS", 30)?.max(1),
        })
    }
}
