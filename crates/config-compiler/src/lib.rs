//! Versioned, transport-independent configuration intent and sing-box renderer.
//!
//! The compiler owns validation and deterministic output. Agent process control
//! is deliberately outside this crate; a rendered config is an untrusted
//! artifact until its signed envelope has been verified by the node runtime.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub mod adapters;
use adapters::singbox::SingBoxAdapter;

/// Compile a shared profile into its sing-box JSON representation.
pub fn compile_config(profile: &ConfigProfile) -> Result<Value, CompileError> {
    SingBoxAdapter.render_json(profile)
}

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("profile must contain at least one inbound")]
    EmptyInbounds,
    #[error("inbound tag is empty")]
    EmptyTag,
    #[error("inbound listen port is invalid")]
    InvalidPort,
    #[error("inbound type is unsupported: {0}")]
    UnsupportedInbound(String),
    #[error("TLS requires certificate and key paths")]
    IncompleteTls,
    #[error("inbound listen port conflicts with the V2Ray API")]
    V2rayApiPortConflict,
    #[error("template must not define experimental.v2ray_api")]
    TemplateOwnsV2rayApi,
    #[error("experimental must be an object")]
    InvalidExperimental,
    #[error("inbound credential fields are invalid for protocol {0}")]
    InvalidInboundCredential(String),
    #[error("outbound type is unsupported: {0}")]
    UnsupportedOutbound(String),
    #[error("outbound credential fields are invalid for protocol {0}")]
    InvalidOutboundCredential(String),
    #[error("invalid rendered sing-box configuration")]
    InvalidRenderedConfig,
    #[error("sing-box validation failed: {0}")]
    SingBoxCheckFailed(String),
    #[error("invalid signed envelope")]
    InvalidEnvelope,
    #[error("signature verification failed")]
    SignatureMismatch,
    #[error("signed envelope content hash does not match payload")]
    ContentHashMismatch,
    #[error("envelope was issued too far in the future")]
    EnvelopeNotYetValid,
    #[error("envelope has expired")]
    EnvelopeExpired,
}

/// The agent-side usage collector connects to this loopback-only V2Ray API.
pub const V2RAY_API_LISTEN: &str = "127.0.0.1:10085";
const V2RAY_API_PORT: u16 = 10085;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigProfile {
    pub schema_version: u32,
    pub node_id: Uuid,
    pub generation: u64,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
    #[serde(default)]
    pub experimental: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inbound {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    #[serde(rename = "type")]
    pub inbound_type: String,
    #[serde(default)]
    pub method: Option<String>,
    pub transport: Transport,
    pub tls: Option<TlsConfig>,
    pub credential: Credential,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Transport {
    Tcp,
    Websocket { path: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub certificate_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboundUser {
    pub name: String,
    #[serde(default)]
    pub uuid: Option<Uuid>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub alter_id: Option<u16>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum Credential {
    #[default]
    None,
    Password {
        username: String,
        password: String,
    },
    Uuid {
        uuid: Uuid,
    },
    Users {
        users: Vec<InboundUser>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub outbound_type: String,
    pub tag: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub credential: Credential,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Route {
    pub final_tag: Option<String>,
}

impl ConfigProfile {
    pub fn validate(&self) -> Result<(), CompileError> {
        if self.inbounds.is_empty() {
            return Err(CompileError::EmptyInbounds);
        }
        if let Some(experimental) = &self.experimental {
            let Some(experimental) = experimental.as_object() else {
                return Err(CompileError::InvalidExperimental);
            };
            if experimental.contains_key("v2ray_api") {
                return Err(CompileError::TemplateOwnsV2rayApi);
            }
        }
        for inbound in &self.inbounds {
            if inbound.tag.trim().is_empty() {
                return Err(CompileError::EmptyTag);
            }
            if inbound.listen_port == 0 {
                return Err(CompileError::InvalidPort);
            }
            if inbound.listen_port == V2RAY_API_PORT {
                return Err(CompileError::V2rayApiPortConflict);
            }
            if !matches!(
                inbound.inbound_type.as_str(),
                "vless" | "vmess" | "trojan" | "shadowsocks" | "mixed"
            ) {
                return Err(CompileError::UnsupportedInbound(
                    inbound.inbound_type.clone(),
                ));
            }
            validate_inbound_credential(inbound)?;
            if let Some(tls) = &inbound.tls {
                if tls.enabled && (tls.certificate_path.is_none() || tls.key_path.is_none()) {
                    return Err(CompileError::IncompleteTls);
                }
            }
        }
        for outbound in &self.outbounds {
            validate_outbound_type(&outbound.outbound_type)?;
        }
        Ok(())
    }

    pub fn render_sing_box(&self) -> Result<Value, CompileError> {
        SingBoxAdapter.render_json(self)
    }

    pub(crate) fn render_sing_box_value(&self) -> Result<Value, CompileError> {
        self.validate()?;
        let inbounds = self
            .inbounds
            .iter()
            .map(render_inbound)
            .collect::<Result<Vec<_>, _>>()?;
        let outbounds = if self.outbounds.is_empty() {
            vec![json!({"type": "direct", "tag": "direct"})]
        } else {
            self.outbounds
                .iter()
                .map(render_outbound)
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut rendered = json!({
            "log": {"level": "info", "timestamp": true},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"final": self.route.final_tag.clone().unwrap_or_else(|| "direct".to_owned())}
        });
        if let Some(experimental) = &self.experimental {
            rendered["experimental"] = experimental.clone();
        } else {
            rendered["experimental"] = json!({});
        }
        let stats_users = rendered["inbounds"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|inbound| {
                inbound["users"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|user| user["name"].as_str().or_else(|| user["username"].as_str()))
                    .map(str::to_owned)
            })
            .collect::<std::collections::BTreeSet<_>>();
        rendered["experimental"]["v2ray_api"] = json!({
            "listen": V2RAY_API_LISTEN,
            "stats": {"enabled": true, "users": stats_users.into_iter().collect::<Vec<_>>()}
        });
        Ok(rendered)
    }
}

fn validate_outbound_type(outbound_type: &str) -> Result<(), CompileError> {
    if matches!(
        outbound_type,
        "direct"
            | "block"
            | "dns"
            | "socks"
            | "http"
            | "shadowsocks"
            | "vless"
            | "vmess"
            | "trojan"
    ) {
        Ok(())
    } else {
        Err(CompileError::UnsupportedOutbound(outbound_type.to_owned()))
    }
}

fn render_outbound(outbound: &Outbound) -> Result<Value, CompileError> {
    let mut value = json!({"type": outbound.outbound_type, "tag": outbound.tag});
    if let Some(method) = &outbound.method {
        value["method"] = json!(method);
    }
    match (&outbound.outbound_type[..], &outbound.credential) {
        (_, Credential::None) => {}
        ("vless", Credential::Uuid { uuid }) => value["uuid"] = json!(uuid),
        ("vmess", Credential::Uuid { uuid }) => {
            value["uuid"] = json!(uuid);
            value["alter_id"] = json!(0);
        }
        (
            "trojan",
            Credential::Password {
                username: _,
                password,
            },
        ) => {
            value["password"] = json!(password);
        }
        (
            "shadowsocks",
            Credential::Password {
                username: _,
                password,
            },
        ) => {
            value["password"] = json!(password);
        }
        ("socks" | "http", Credential::Password { username, password }) => {
            value["username"] = json!(username);
            value["password"] = json!(password);
        }
        (protocol, _) => return Err(CompileError::InvalidOutboundCredential(protocol.to_owned())),
    }
    Ok(value)
}

fn valid_shadowsocks_2022_key(method: &str, key: &str) -> bool {
    let expected_len = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return true,
    };
    BASE64
        .decode(key)
        .is_ok_and(|decoded| decoded.len() == expected_len)
}
fn validate_inbound_credential(inbound: &Inbound) -> Result<(), CompileError> {
    match (&inbound.inbound_type[..], &inbound.credential) {
        (_, Credential::None) => Ok(()),
        ("vless", Credential::Uuid { .. }) => Ok(()),
        ("vmess", Credential::Uuid { .. }) => Ok(()),
        ("trojan", Credential::Password { username, password })
            if !username.trim().is_empty() && !password.is_empty() =>
        {
            Ok(())
        }
        ("shadowsocks", Credential::Password { username, password })
            if !username.trim().is_empty()
                && !password.is_empty()
                && inbound.method.as_deref().is_some_and(|method| {
                    !method.starts_with("2022-") || valid_shadowsocks_2022_key(method, password)
                })
                && inbound
                    .method
                    .as_deref()
                    .is_some_and(|method| !method.is_empty()) =>
        {
            Ok(())
        }
        ("mixed", Credential::Password { username, password })
            if !username.is_empty() && !password.is_empty() =>
        {
            Ok(())
        }
        (protocol, Credential::Users { users }) => {
            if users.is_empty() {
                return Ok(());
            }
            let valid = users.iter().all(|user| match protocol {
                "vless" => {
                    !user.name.trim().is_empty()
                        && user.uuid.is_some()
                        && user.password.is_none()
                        && user.alter_id.is_none()
                }
                "vmess" => {
                    !user.name.trim().is_empty() && user.uuid.is_some() && user.password.is_none()
                }
                "trojan" => {
                    !user.name.trim().is_empty()
                        && user
                            .password
                            .as_deref()
                            .is_some_and(|password| !password.is_empty())
                        && user.uuid.is_none()
                }
                "shadowsocks" => {
                    !user.name.trim().is_empty()
                        && user.password.as_deref().is_some_and(|password| {
                            !password.is_empty()
                                && inbound.method.as_deref().is_some_and(|method| {
                                    valid_shadowsocks_2022_key(method, password)
                                })
                        })
                        && user.uuid.is_none()
                }
                "mixed" => {
                    !user.name.trim().is_empty()
                        && user
                            .password
                            .as_deref()
                            .is_some_and(|password| !password.is_empty())
                        && user.uuid.is_none()
                }
                _ => false,
            });
            if valid {
                Ok(())
            } else {
                Err(CompileError::InvalidInboundCredential(protocol.to_owned()))
            }
        }
        (protocol, _) => Err(CompileError::InvalidInboundCredential(protocol.to_owned())),
    }
}

fn render_inbound(inbound: &Inbound) -> Result<Value, CompileError> {
    let mut value = json!({
        "type": inbound.inbound_type,
        "tag": inbound.tag,
        "listen": inbound.listen,
        "listen_port": inbound.listen_port,
    });
    if let Some(method) = &inbound.method {
        value["method"] = json!(method);
    }
    match &inbound.transport {
        Transport::Tcp => {}
        Transport::Websocket { path } => value["transport"] = json!({"type": "ws", "path": path}),
    }
    if let Some(tls) = &inbound.tls {
        if tls.enabled {
            value["tls"] = adapters::singbox::tls_value(
                &tls.server_name,
                &tls.certificate_path,
                &tls.key_path,
            );
        }
    }
    match &inbound.credential {
        Credential::None => {}
        Credential::Password { username, password } => match inbound.inbound_type.as_str() {
            "trojan" => value["users"] = json!([{"name": username, "password": password}]),
            "shadowsocks" => {
                value["password"] = json!(password);
                value["users"] = json!([{"name": username, "password": password}]);
            }
            "mixed" => value["users"] = json!([{"username": username, "password": password}]),
            protocol => return Err(CompileError::InvalidInboundCredential(protocol.to_owned())),
        },
        Credential::Uuid { uuid } => match inbound.inbound_type.as_str() {
            "vless" => value["users"] = json!([{"name": uuid.to_string(), "uuid": uuid}]),
            "vmess" => {
                value["users"] = json!([{"name": uuid.to_string(), "uuid": uuid, "alter_id": 0}])
            }
            protocol => return Err(CompileError::InvalidInboundCredential(protocol.to_owned())),
        },
        Credential::Users { users } => {
            value["users"] = match inbound.inbound_type.as_str() {
                "vless" => json!(users.iter().map(|user| json!({"name": user.name, "uuid": user.uuid})).collect::<Vec<_>>()),
                "vmess" => json!(users.iter().map(|user| json!({"name": user.name, "uuid": user.uuid, "alter_id": user.alter_id.unwrap_or(0)})).collect::<Vec<_>>()),
                "trojan" | "shadowsocks" => json!(users.iter().map(|user| json!({"name": user.name, "password": user.password})).collect::<Vec<_>>()),
                "mixed" => json!(users.iter().map(|user| json!({"username": user.name, "password": user.password})).collect::<Vec<_>>()),
                protocol => return Err(CompileError::InvalidInboundCredential(protocol.to_owned())),
            };
        }
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedConfigEnvelope {
    pub key_id: String,
    pub content_hash: String,
    pub target_node: Uuid,
    pub generation: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedConfigEnvelope {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let payload = BASE64.encode(&self.payload);
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.key_id,
            self.content_hash,
            self.target_node,
            self.generation,
            self.issued_at,
            self.expires_at,
            payload
        )
        .into_bytes()
    }

    pub fn sign(
        signing_key: &SigningKey,
        key_id: impl Into<String>,
        target_node: Uuid,
        generation: u64,
        issued_at: i64,
        expires_at: i64,
        payload: Vec<u8>,
    ) -> Self {
        let content_hash = hex_hash(&payload);
        let mut envelope = Self {
            key_id: key_id.into(),
            content_hash,
            target_node,
            generation,
            issued_at,
            expires_at,
            payload,
            signature: Vec::new(),
        };
        envelope.signature = signing_key
            .sign(&envelope.canonical_bytes())
            .to_bytes()
            .to_vec();
        envelope
    }

    pub fn verify(&self, key: &VerifyingKey, now: i64) -> Result<(), CompileError> {
        if hex_hash(&self.payload) != self.content_hash
            || self.issued_at > now
            || self.expires_at < self.issued_at
            || self.expires_at < now
            || self.signature.len() != 64
        {
            return Err(CompileError::InvalidEnvelope);
        }
        self.verify_signature(key)
    }

    pub fn verify_with_skew(
        &self,
        key: &VerifyingKey,
        now: i64,
        skew_secs: i64,
    ) -> Result<(), CompileError> {
        if hex_hash(&self.payload) != self.content_hash {
            return Err(CompileError::ContentHashMismatch);
        }
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| CompileError::InvalidEnvelope)?;
        key.verify(&self.canonical_bytes(), &signature)
            .map_err(|_| CompileError::SignatureMismatch)?;
        let skew = skew_secs.max(0);
        if self.issued_at > now.saturating_add(skew) {
            return Err(CompileError::EnvelopeNotYetValid);
        }
        if self.expires_at < self.issued_at || self.expires_at < now.saturating_sub(skew) {
            return Err(CompileError::EnvelopeExpired);
        }
        Ok(())
    }

    fn verify_signature(&self, key: &VerifyingKey) -> Result<(), CompileError> {
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| CompileError::InvalidEnvelope)?;
        key.verify(&self.canonical_bytes(), &signature)
            .map_err(|_| CompileError::SignatureMismatch)
    }
}

pub fn hex_hash(payload: &[u8]) -> String {
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::{fs, process::Command};

    fn profile() -> ConfigProfile {
        ConfigProfile {
            schema_version: 1,
            node_id: Uuid::from_u128(1),
            generation: 3,
            inbounds: vec![Inbound {
                tag: "vless-in".to_owned(),
                listen: "0.0.0.0".to_owned(),
                listen_port: 443,
                inbound_type: "vless".to_owned(),
                method: None,
                transport: Transport::Websocket {
                    path: "/ws".to_owned(),
                },
                tls: None,
                credential: Credential::Uuid {
                    uuid: Uuid::from_u128(2),
                },
            }],
            outbounds: vec![],
            route: Route::default(),
            experimental: None,
        }
    }

    fn protocol_profile(protocol: &str) -> ConfigProfile {
        let mut profile = profile();
        let inbound = &mut profile.inbounds[0];
        inbound.inbound_type = protocol.to_owned();
        inbound.transport = Transport::Tcp;
        inbound.tls = None;
        inbound.credential = match protocol {
            "vless" | "vmess" => Credential::Uuid {
                uuid: Uuid::from_u128(2),
            },
            "trojan" => Credential::Users {
                users: vec![InboundUser {
                    name: Uuid::from_u128(3).to_string(),
                    uuid: None,
                    password: Some("trojan-secret".into()),
                    alter_id: None,
                }],
            },
            "shadowsocks" => {
                inbound.method = Some("2022-blake3-aes-128-gcm".into());
                Credential::Password {
                    username: Uuid::from_u128(3).to_string(),
                    password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
                }
            }
            "mixed" => Credential::Password {
                username: Uuid::from_u128(3).to_string(),
                password: "mixed-secret".into(),
            },
            _ => unreachable!(),
        };
        profile
    }

    fn sing_box_binary() -> Option<std::path::PathBuf> {
        let configured = std::env::var_os("CYBERBOARD_SING_BOX_BINARY");
        let binary = configured
            .map(std::path::PathBuf::from)
            .or_else(|| Some(std::path::PathBuf::from("sing-box")))?;
        let output = Command::new(&binary).arg("version").output().ok()?;
        let version = String::from_utf8_lossy(&output.stdout);
        if !version.contains("with_v2ray_api") {
            eprintln!("skipped sing-box check: {binary:?} lacks with_v2ray_api");
            return None;
        }
        Some(binary)
    }

    fn check_with_sing_box(config: &Value) {
        let Some(binary) = sing_box_binary() else {
            return;
        };
        let path =
            std::env::temp_dir().join(format!("cyberboard-sing-box-{}.json", Uuid::new_v4()));
        fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap();
        let output = Command::new(binary)
            .arg("check")
            .arg("-c")
            .arg(&path)
            .output()
            .unwrap();
        let _ = fs::remove_file(&path);
        assert!(
            output.status.success(),
            "sing-box check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn skew_tolerant_verification_checks_boundaries_and_failure_kinds() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let payload = b"{}".to_vec();
        let key = signing_key.verifying_key();
        let future = SignedConfigEnvelope::sign(
            &signing_key,
            "k",
            Uuid::from_u128(1),
            1,
            130,
            200,
            payload.clone(),
        );
        assert!(future.verify_with_skew(&key, 100, 30).is_ok());
        let too_future = SignedConfigEnvelope::sign(
            &signing_key,
            "k",
            Uuid::from_u128(1),
            1,
            220,
            300,
            payload.clone(),
        );
        assert!(matches!(
            too_future.verify_with_skew(&key, 100, 60),
            Err(CompileError::EnvelopeNotYetValid)
        ));
        let expiring = SignedConfigEnvelope::sign(
            &signing_key,
            "k",
            Uuid::from_u128(1),
            1,
            0,
            70,
            payload.clone(),
        );
        assert!(expiring.verify_with_skew(&key, 100, 30).is_ok());
        let expired = SignedConfigEnvelope::sign(
            &signing_key,
            "k",
            Uuid::from_u128(1),
            1,
            0,
            0,
            payload.clone(),
        );
        assert!(matches!(
            expired.verify_with_skew(&key, 120, 60),
            Err(CompileError::EnvelopeExpired)
        ));
        let mut bad_hash = future.clone();
        bad_hash.content_hash = "wrong".into();
        assert!(matches!(
            bad_hash.verify_with_skew(&key, 100, 60),
            Err(CompileError::ContentHashMismatch)
        ));
        let mut bad_signature = future;
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            bad_signature.verify_with_skew(&key, 100, 60),
            Err(CompileError::SignatureMismatch)
        ));
    }

    #[test]
    fn renders_a_valid_sing_box_server_config() {
        let rendered = profile().render_sing_box().unwrap();
        assert_eq!(rendered["inbounds"][0]["type"], "vless");
        assert_eq!(rendered["inbounds"][0]["transport"]["path"], "/ws");
        assert_eq!(rendered["outbounds"][0]["type"], "direct");
    }

    #[test]
    fn rejects_invalid_profile() {
        let mut invalid = profile();
        invalid.inbounds[0].listen_port = 0;
        assert!(matches!(
            invalid.render_sing_box(),
            Err(CompileError::InvalidPort)
        ));
    }

    #[test]
    fn renders_and_checks_protocol_samples() {
        for protocol in ["vless", "vmess", "trojan", "shadowsocks", "mixed"] {
            let rendered = protocol_profile(protocol).render_sing_box().unwrap();
            assert_eq!(
                rendered["experimental"]["v2ray_api"]["listen"],
                V2RAY_API_LISTEN
            );
            let expected_name = if matches!(protocol, "vless" | "vmess") {
                Uuid::from_u128(2).to_string()
            } else {
                Uuid::from_u128(3).to_string()
            };
            assert_eq!(
                rendered["experimental"]["v2ray_api"]["stats"]["users"][0],
                expected_name
            );
            if protocol == "trojan" {
                assert!(
                    rendered["inbounds"][0]["users"][0]
                        .get("username")
                        .is_none()
                );
            }
            if protocol == "vmess" {
                assert_eq!(rendered["inbounds"][0]["users"][0]["alter_id"], 0);
            }
            check_with_sing_box(&rendered);
        }
    }

    #[test]
    fn checks_config_after_all_authenticated_inbounds_are_removed() {
        let empty_config = json!({
            "log": {"level": "error"},
            "inbounds": [],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
            "experimental": {
                "v2ray_api": {
                    "listen": V2RAY_API_LISTEN,
                    "stats": {"enabled": true, "users": []}
                }
            }
        });
        check_with_sing_box(&empty_config);
    }

    #[test]
    fn merges_other_experimental_fields_but_owns_v2ray_api() {
        let mut profile = profile();
        profile.experimental =
            Some(json!({"clash_api": {"external_controller": "127.0.0.1:9090"}}));
        let rendered = profile.render_sing_box().unwrap();
        assert!(rendered["experimental"]["clash_api"].is_object());
        assert!(rendered["experimental"]["v2ray_api"].is_object());
        profile.experimental = Some(json!({"v2ray_api": {}}));
        assert!(matches!(
            profile.validate(),
            Err(CompileError::TemplateOwnsV2rayApi)
        ));
    }

    #[test]
    fn rejects_v2ray_api_port_conflict() {
        let mut profile = profile();
        profile.inbounds[0].listen_port = 10085;
        assert!(matches!(
            profile.validate(),
            Err(CompileError::V2rayApiPortConflict)
        ));
    }

    fn run_proxy_round_trip(binary: &std::path::Path, protocol: &str) {
        let user_id = Uuid::from_u128(10).to_string();
        let user_uuid = Uuid::from_u128(11).to_string();
        let user_password = "trojan-e2e-password";
        let server_password = "AAAAAAAAAAAAAAAAAAAAAA==";
        let user_ss_password = "AQEBAQEBAQEBAQEBAQEBAQ==";
        let (server_port, client_port) = match protocol {
            "vless" => (18110, 18111),
            "shadowsocks" => (18112, 18113),
            "shadowsocks-legacy" => (18116, 18117),
            "trojan" => (18114, 18115),
            _ => unreachable!(),
        };
        let inbound_type = if protocol == "shadowsocks-legacy" {
            "shadowsocks"
        } else {
            protocol
        };
        let mut server_inbound = json!({
            "type": inbound_type,
            "tag": "proxy-in",
            "listen": "127.0.0.1",
            "listen_port": server_port,
        });
        let mut client_outbound = json!({
            "type": inbound_type,
            "tag": "proxy-out",
            "server": "127.0.0.1",
            "server_port": server_port,
        });
        match protocol {
            "vless" => {
                server_inbound["users"] = json!([{"name": user_id, "uuid": user_uuid}]);
                client_outbound["uuid"] = json!(user_uuid);
            }
            "shadowsocks" => {
                server_inbound["method"] = json!("2022-blake3-aes-128-gcm");
                server_inbound["password"] = json!(server_password);
                server_inbound["users"] = json!([{"name": user_id, "password": user_ss_password}]);
                client_outbound["method"] = json!("2022-blake3-aes-128-gcm");
                client_outbound["password"] =
                    json!(format!("{server_password}:{user_ss_password}"));
            }
            "shadowsocks-legacy" => {
                server_inbound["method"] = json!("aes-256-gcm");
                server_inbound["password"] = json!(server_password);
                server_inbound["users"] = json!([{"name": user_id, "password": user_ss_password}]);
                client_outbound["method"] = json!("aes-256-gcm");
                client_outbound["password"] = json!(user_ss_password);
            }
            "trojan" => {
                let temp = std::env::temp_dir();
                let cert = temp.join("cyberboard-e2e-cert.pem");
                let key = temp.join("cyberboard-e2e-key.pem");
                let openssl = Command::new("openssl")
                    .args([
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-subj",
                        "/CN=localhost",
                        "-keyout",
                    ])
                    .arg(&key)
                    .args(["-out"])
                    .arg(&cert)
                    .args(["-days", "1"])
                    .output()
                    .expect("run openssl");
                assert!(openssl.status.success(), "openssl failed");
                server_inbound["users"] = json!([{"name": user_id, "password": user_password}]);
                server_inbound["tls"] = json!({
                    "enabled": true,
                    "certificate_path": cert,
                    "key_path": key,
                });
                client_outbound["password"] = json!(user_password);
                client_outbound["tls"] =
                    json!({"enabled": true, "server_name": "localhost", "insecure": true});
            }
            _ => unreachable!(),
        }
        let server = json!({
            "log": {"level": "error"},
            "inbounds": [server_inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
            "experimental": {"v2ray_api": {"listen": V2RAY_API_LISTEN, "stats": {"enabled": true, "users": [user_id]}}}
        });
        let client = json!({
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": client_port}],
            "outbounds": [client_outbound],
            "route": {"final": "proxy-out"}
        });
        let suffix = format!("{}-{}", protocol, Uuid::new_v4());
        let server_path = std::env::temp_dir().join(format!("cyberboard-e2e-server-{suffix}.json"));
        let client_path = std::env::temp_dir().join(format!("cyberboard-e2e-client-{suffix}.json"));
        fs::write(&server_path, serde_json::to_vec(&server).unwrap()).unwrap();
        fs::write(&client_path, serde_json::to_vec(&client).unwrap()).unwrap();
        let mut http = Command::new("python3")
            .args(["-m", "http.server", "18119", "--bind", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start local HTTP server");
        let mut server_process = Command::new(binary)
            .args(["run", "-c"])
            .arg(&server_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start sing-box server");
        let mut client_process = Command::new(binary)
            .args(["run", "-c"])
            .arg(&client_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start sing-box client");
        let mut connected = false;
        for _ in 0..40 {
            let curl = Command::new("curl")
                .args([
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "1",
                    "--socks5-hostname",
                    &format!("127.0.0.1:{client_port}"),
                    "http://127.0.0.1:18119",
                ])
                .output();
            if curl.is_ok_and(|output| output.status.success()) {
                connected = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = client_process.kill();
        let _ = server_process.kill();
        let _ = http.kill();
        let _ = client_process.wait();
        let _ = server_process.wait();
        let _ = http.wait();
        let _ = fs::remove_file(&server_path);
        let _ = fs::remove_file(&client_path);
        let _ = fs::remove_file(std::env::temp_dir().join("cyberboard-e2e-cert.pem"));
        let _ = fs::remove_file(std::env::temp_dir().join("cyberboard-e2e-key.pem"));
        assert!(connected, "{protocol} sing-box round trip did not connect");
    }

    #[test]
    fn proxy_round_trips_cover_credentials_and_transports() {
        let Some(binary) = sing_box_binary() else {
            return;
        };
        for protocol in ["vless", "shadowsocks", "shadowsocks-legacy", "trojan"] {
            run_proxy_round_trip(&binary, protocol);
        }
    }

    #[test]
    fn signs_and_verifies_canonical_envelope() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let payload = serde_json::to_vec(&profile().render_sing_box().unwrap()).unwrap();
        let envelope = SignedConfigEnvelope::sign(
            &signing_key,
            "dev-test",
            Uuid::from_u128(1),
            3,
            100,
            200,
            payload,
        );
        assert!(envelope.verify(&signing_key.verifying_key(), 150).is_ok());
        let wire = serde_json::to_vec(&envelope).unwrap();
        let decoded: SignedConfigEnvelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(decoded, envelope);
        assert!(decoded.verify(&signing_key.verifying_key(), 150).is_ok());
        assert!(envelope.verify(&signing_key.verifying_key(), 201).is_err());

        let future = SignedConfigEnvelope::sign(
            &signing_key,
            "dev-test",
            Uuid::from_u128(1),
            3,
            200,
            300,
            serde_json::to_vec(&profile().render_sing_box().unwrap()).unwrap(),
        );
        assert!(future.verify(&signing_key.verifying_key(), 150).is_err());

        let invalid_window = SignedConfigEnvelope::sign(
            &signing_key,
            "dev-test",
            Uuid::from_u128(1),
            3,
            200,
            100,
            serde_json::to_vec(&profile().render_sing_box().unwrap()).unwrap(),
        );
        assert!(
            invalid_window
                .verify(&signing_key.verifying_key(), 150)
                .is_err()
        );
    }
}
