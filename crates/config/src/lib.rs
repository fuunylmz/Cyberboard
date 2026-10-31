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

    #[error("invalid tenant id: {0}")]
    InvalidTenantId(uuid::Error),

    #[error("invalid bind address: {0}")]
    InvalidBindAddress(#[from] std::net::AddrParseError),

    #[error("invalid boolean for {field}: {value}")]
    InvalidBoolean { field: &'static str, value: String },
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

fn env_bool(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match optional_env(name) {
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::InvalidBoolean { field: name, value }),
        },
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
    pub agent_grpc_addr: String,
    pub agent_grpc_server_cert: Option<String>,
    pub agent_grpc_server_key: Option<String>,
    pub agent_grpc_client_ca: Option<String>,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub demo_admin_email: String,
    pub demo_admin_password: String,
    pub demo_user_email: String,
    pub demo_user_password: String,
    pub dev_mode: bool,
    pub tenant_id: Uuid,
}

impl ApiConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            bind_addr: env_bind_addr(),
            port: env_u16("CYBERBOARD_API_PORT", 8080)?,
            agent_grpc_addr: optional_env("CYBERBOARD_AGENT_GRPC_ADDR")
                .unwrap_or_else(|| "0.0.0.0:9090".to_owned()),
            agent_grpc_server_cert: optional_env("CYBERBOARD_AGENT_GRPC_SERVER_CERT"),
            agent_grpc_server_key: optional_env("CYBERBOARD_AGENT_GRPC_SERVER_KEY"),
            agent_grpc_client_ca: optional_env("CYBERBOARD_AGENT_GRPC_CLIENT_CA"),
            database_url: optional_env("CYBERBOARD_DATABASE_URL"),
            redis_url: optional_env("CYBERBOARD_REDIS_URL"),
            demo_admin_email: optional_env("CYBERBOARD_DEMO_ADMIN_EMAIL")
                .unwrap_or_else(|| "admin@example.com".to_owned()),
            demo_admin_password: optional_env("CYBERBOARD_DEMO_ADMIN_PASSWORD")
                .unwrap_or_else(|| "password".to_owned()),
            demo_user_email: optional_env("CYBERBOARD_DEMO_USER_EMAIL")
                .unwrap_or_else(|| "lin@example.com".to_owned()),
            demo_user_password: optional_env("CYBERBOARD_DEMO_USER_PASSWORD")
                .unwrap_or_else(|| "password".to_owned()),
            dev_mode: env_bool("CYBERBOARD_DEV_MODE", false)?,
            tenant_id: optional_env("CYBERBOARD_TENANT_ID")
                .map(|value| Uuid::parse_str(&value))
                .transpose()?
                .unwrap_or_else(|| Uuid::from_u128(1)),
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
    pub tenant_id: Uuid,
}

impl WorkerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            interval_secs: env_u64("CYBERBOARD_WORKER_INTERVAL_SECS", 30)?.max(1),
            database_url: optional_env("CYBERBOARD_DATABASE_URL"),
            redis_url: optional_env("CYBERBOARD_REDIS_URL"),
            tenant_id: optional_env("CYBERBOARD_TENANT_ID")
                .map(|value| Uuid::parse_str(&value).map_err(ConfigError::InvalidTenantId))
                .transpose()?
                .unwrap_or_else(|| Uuid::from_u128(1)),
        })
    }
}

#[derive(Clone)]
pub struct AgentConfig {
    pub control_plane_url: String,
    pub node_id: Option<Uuid>,
    pub interval_secs: u64,
    pub ca_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub tls_server_name: Option<String>,
    pub identity_path: String,
    pub insecure: bool,
}

impl AgentConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let node_id = optional_env("CYBERBOARD_NODE_ID")
            .map(|value| Uuid::parse_str(&value))
            .transpose()?;

        Ok(Self {
            control_plane_url: optional_env("CYBERBOARD_CONTROL_PLANE_URL")
                .unwrap_or_else(|| "https://127.0.0.1:9090".to_owned()),
            node_id,
            interval_secs: env_u64("CYBERBOARD_AGENT_INTERVAL_SECS", 30)?.max(1),
            ca_cert_path: optional_env("CYBERBOARD_AGENT_CA_CERT"),
            client_cert_path: optional_env("CYBERBOARD_AGENT_CLIENT_CERT"),
            client_key_path: optional_env("CYBERBOARD_AGENT_CLIENT_KEY"),
            tls_server_name: optional_env("CYBERBOARD_AGENT_TLS_SERVER_NAME"),
            identity_path: optional_env("CYBERBOARD_AGENT_IDENTITY_PATH")
                .unwrap_or_else(|| "/var/lib/cyberboard/agent-identity.json".to_owned()),
            insecure: env_bool("CYBERBOARD_AGENT_INSECURE", false)?,
        })
    }
}
