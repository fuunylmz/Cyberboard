use base64::{Engine as _, engine::general_purpose::STANDARD};
use cyberboard_config_compiler::SignedConfigEnvelope;
use ed25519_dalek::SigningKey;
use uuid::Uuid;
#[derive(Debug)]
pub enum SignerError {
    InvalidBase64,
    InvalidLength,
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBase64 => "CYBERBOARD_CONFIG_SIGNING_KEY is not valid standard base64",
            Self::InvalidLength => "CYBERBOARD_CONFIG_SIGNING_KEY must decode to exactly 32 bytes",
        })
    }
}

impl std::error::Error for SignerError {}

pub struct ConfigSigner {
    key: SigningKey,
    key_id: String,
    ttl_secs: u64,
}

impl ConfigSigner {
    pub fn from_env(ttl_secs: u64) -> Result<Option<Self>, SignerError> {
        let encoded = std::env::var("CYBERBOARD_CONFIG_SIGNING_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let Some(seed) = parse_seed(encoded.as_deref())? else {
            return Ok(None);
        };
        let key_id = std::env::var("CYBERBOARD_CONFIG_SIGNING_KEY_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "config-key-1".to_owned());
        Ok(Some(Self {
            key: SigningKey::from_bytes(&seed),
            key_id,
            ttl_secs: ttl_secs.clamp(60, 3600),
        }))
    }

    #[cfg(test)]
    pub fn from_seed(seed: [u8; 32], key_id: String, ttl_secs: u64) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            key_id,
            ttl_secs: ttl_secs.clamp(60, 3600),
        }
    }

    pub fn sign(
        &self,
        node_id: Uuid,
        generation: u64,
        payload: Vec<u8>,
        issued_at: i64,
    ) -> SignedConfigEnvelope {
        SignedConfigEnvelope::sign(
            &self.key,
            self.key_id.clone(),
            node_id,
            generation,
            issued_at,
            issued_at + self.ttl_secs as i64,
            payload,
        )
    }

    #[cfg(test)]
    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.verifying_key()
    }
}

fn parse_seed(encoded: Option<&str>) -> Result<Option<[u8; 32]>, SignerError> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| SignerError::InvalidBase64)?;
    Ok(Some(
        bytes.try_into().map_err(|_| SignerError::InvalidLength)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_envelope_with_ttl_and_key_id() {
        let signer = ConfigSigner::from_seed([7; 32], "unit-test".into(), 120);
        let envelope = signer.sign(Uuid::from_u128(2), 4, b"{}".to_vec(), 1000);
        assert_eq!(envelope.expires_at, 1120);
        assert_eq!(envelope.key_id, "unit-test");
        envelope.verify(&signer.key.verifying_key(), 1000).unwrap();
    }

    #[test]
    fn ttl_is_clamped_and_seed_shape_is_checked() {
        assert_eq!(ConfigSigner::from_seed([0; 32], "k".into(), 1).ttl_secs, 60);
        assert_eq!(
            ConfigSigner::from_seed([0; 32], "k".into(), 4000).ttl_secs,
            3600
        );
        let encoded = STANDARD.encode([1; 32]);
        assert_eq!(parse_seed(Some(&encoded)).unwrap(), Some([1; 32]));
        assert!(matches!(
            parse_seed(Some("not base64!")),
            Err(SignerError::InvalidBase64)
        ));
        let short = STANDARD.encode([1; 31]);
        assert!(matches!(
            parse_seed(Some(&short)),
            Err(SignerError::InvalidLength)
        ));
        assert_eq!(parse_seed(None).unwrap(), None);
    }
}
