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
    #[error("outbound credential fields are invalid for protocol {0}")]
    InvalidOutboundCredential(String),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Credential {
    None,
    Password { username: String, password: String },
    Uuid { uuid: Uuid },
    Users { users: Vec<InboundUser> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub outbound_type: String,
    pub tag: String,
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
                .map(|item| json!({"type": item.outbound_type, "tag": item.tag}))
                .collect()
        };
        let mut rendered = json!({
            "log": {"level": "info"},
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
        "direct" | "block" | "dns" | "socks" | "http" | "shadowsocks" | "vless" | "vmess" | "trojan"
    ) {
        Ok(())
    } else {
        Err(CompileError::UnsupportedInbound(outbound_type.to_owned()))
    }
}

fn validate_inbound_credential(inbound: &Inbound) -> Result<(), CompileError> {
    match (&inbound.inbound_type[..], &inbound.credential) {
        (_, Credential::None) => Ok(()),
        ("vless", Credential::Uuid { .. }) => Ok(()),
        ("vmess", Credential::Uuid { .. }) => Ok(()),
        ("trojan", Credential::Password { username, password })
            if !username.trim().is_empty() && !password.is_empty() => Ok(()),
        ("shadowsocks", Credential::Password { username, password })
            if !username.trim().is_empty()
                && !password.is_empty()
                && inbound.method.as_deref().is_some_and(|method| !method.is_empty()) => Ok(()),
        ("mixed", Credential::Password { username, password })
            if !username.is_empty() && !password.is_empty() => Ok(()),
        (protocol, Credential::Users { users }) => {
            if users.is_empty() {
                return Ok(());
            }
            let valid = users.iter().all(|user| match protocol {
                "vless" => !user.name.trim().is_empty()
                    && user.uuid.is_some()
                    && user.password.is_none()
                    && user.alter_id.is_none(),
                "vmess" => !user.name.trim().is_empty()
                    && user.uuid.is_some()
                    && user.password.is_none(),
                "trojan" | "shadowsocks" => {
                    !user.name.trim().is_empty()
                        && user.password.as_deref().is_some_and(|password| !password.is_empty())
                        && user.uuid.is_none()
                }
                "mixed" => {
                    !user.name.trim().is_empty()
                        && user.password.as_deref().is_some_and(|password| !password.is_empty())
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
            value["tls"] = json!({
                "enabled": true,
                "server_name": tls.server_name,
                "certificate_path": tls.certificate_path,
                "key_path": tls.key_path,
            });
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
            protocol => {
                return Err(CompileError::InvalidInboundCredential(protocol.to_owned()))
            }
        },
        Credential::Uuid { uuid } => match inbound.inbound_type.as_str() {
            "vless" => value["users"] = json!([{"uuid": uuid}]),
            "vmess" => value["users"] = json!([{"uuid": uuid, "alterId": 0}]),
            protocol => {
                return Err(CompileError::InvalidInboundCredential(protocol.to_owned()))
            }
        },
        Credential::Users { users } => {
            value["users"] = match inbound.inbound_type.as_str() {
                "vless" => json!(users.iter().map(|user| json!({"name": user.name, "uuid": user.uuid})).collect::<Vec<_>>()),
                "vmess" => json!(users.iter().map(|user| json!({"name": user.name, "uuid": user.uuid, "alterId": user.alter_id.unwrap_or(0)})).collect::<Vec<_>>()),
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
