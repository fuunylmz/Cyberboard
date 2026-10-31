//! Outbound-only control-plane transport boundary.
//!
//! The concrete tonic client is intentionally deferred until `protoc`/prost
//! generation is available in the build image. This module keeps the protocol
//! semantics testable and prevents the agent from growing an inbound listener.

use cyberboard_config_compiler::SignedConfigEnvelope;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ControlPlaneError {
    #[error("control-plane transport is not configured")]
    NotConfigured,
    #[error("signed desired state failed trust validation")]
    UntrustedDesiredState,
    #[error("generation compare-and-swap rejected")]
    GenerationConflict,
}

#[derive(Clone, Debug)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub node_id: Uuid,
    pub control_plane_url: String,
}

#[derive(Clone, Debug)]
pub struct DesiredStateRequest {
    pub identity: AgentIdentity,
    pub current_generation: u64,
    pub current_content_hash: String,
}

#[derive(Clone, Debug)]
pub struct ApplyResult {
    pub generation: u64,
    pub previous_hash: String,
    pub applied_hash: String,
    pub compare_and_swap_ok: bool,
    pub phase: String,
    pub error_code: Option<String>,
}

pub trait ControlPlaneClient {
    fn endpoint(&self) -> &str;
    fn heartbeat(&self, identity: &AgentIdentity) -> Result<(), ControlPlaneError>;
    fn desired_state(
        &self,
        request: &DesiredStateRequest,
    ) -> Result<Option<SignedConfigEnvelope>, ControlPlaneError>;
    fn report_apply_result(&self, result: &ApplyResult) -> Result<(), ControlPlaneError>;
}

pub struct OutboundTransport {
    endpoint: String,
}

impl OutboundTransport {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
}

impl ControlPlaneClient for OutboundTransport {
    fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn heartbeat(&self, _: &AgentIdentity) -> Result<(), ControlPlaneError> {
        Ok(())
    }
    fn desired_state(
        &self,
        _: &DesiredStateRequest,
    ) -> Result<Option<SignedConfigEnvelope>, ControlPlaneError> {
        Ok(None)
    }
    fn report_apply_result(&self, _: &ApplyResult) -> Result<(), ControlPlaneError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentIdentity, ControlPlaneClient, DesiredStateRequest, OutboundTransport};
    use uuid::Uuid;

    #[test]
    fn transport_is_outbound_only_and_generation_aware() {
        let transport = OutboundTransport::new("https://control.example.invalid");
        let identity = AgentIdentity {
            agent_id: "agent-1".into(),
            node_id: Uuid::from_u128(1),
            control_plane_url: transport.endpoint().into(),
        };
        assert_eq!(transport.endpoint(), identity.control_plane_url);
        assert!(transport.heartbeat(&identity).is_ok());
        assert!(
            transport
                .desired_state(&DesiredStateRequest {
                    identity,
                    current_generation: 4,
                    current_content_hash: "hash".into()
                })
                .unwrap()
                .is_none()
        );
    }
}
