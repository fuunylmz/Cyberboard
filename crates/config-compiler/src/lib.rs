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
    #[error("invalid signed envelope")]
    InvalidEnvelope,
    #[error("signature verification failed")]
    SignatureMismatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigProfile {
    pub schema_version: u32,
    pub node_id: Uuid,
    pub generation: u64,
    pub inbounds: Vec<Inbound>,
    pub outbounds: Vec<Outbound>,
    pub route: Route,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inbound {
    pub tag: String,
    pub listen: String,
    pub listen_port: u16,
    #[serde(rename = "type")]
    pub inbound_type: String,
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
pub enum Credential {
    None,
    Password { username: String, password: String },
    Uuid { uuid: Uuid },
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
        for inbound in &self.inbounds {
            if inbound.tag.trim().is_empty() {
                return Err(CompileError::EmptyTag);
            }
            if inbound.listen_port == 0 {
                return Err(CompileError::InvalidPort);
            }
            if !matches!(
                inbound.inbound_type.as_str(),
                "vless" | "vmess" | "trojan" | "mixed"
            ) {
                return Err(CompileError::UnsupportedInbound(
                    inbound.inbound_type.clone(),
                ));
            }
            if let Some(tls) = &inbound.tls {
                if tls.enabled && (tls.certificate_path.is_none() || tls.key_path.is_none()) {
                    return Err(CompileError::IncompleteTls);
                }
            }
        }
        Ok(())
    }

    pub fn render_sing_box(&self) -> Result<Value, CompileError> {
        self.validate()?;
        let inbounds = self.inbounds.iter().map(render_inbound).collect::<Vec<_>>();
        let outbounds = if self.outbounds.is_empty() {
            vec![json!({"type": "direct", "tag": "direct"})]
        } else {
            self.outbounds
                .iter()
                .map(|item| json!({"type": item.outbound_type, "tag": item.tag}))
                .collect()
        };
        Ok(json!({
            "log": {"level": "info"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"final": self.route.final_tag.clone().unwrap_or_else(|| "direct".to_owned())}
        }))
    }
}

fn render_inbound(inbound: &Inbound) -> Value {
    let mut value = json!({
        "type": inbound.inbound_type,
        "tag": inbound.tag,
        "listen": inbound.listen,
        "listen_port": inbound.listen_port,
    });
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
        Credential::Password { username, password } => {
            value["users"] = json!([{"username": username, "password": password}])
        }
        Credential::Uuid { uuid } => value["users"] = json!([{"uuid": uuid}]),
    }
    value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        }
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
