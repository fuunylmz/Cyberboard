use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use cyberboard_agent_protocol::{
    PROTOCOL_VERSION,
    generated::{
        Ack, DesiredStateResponse, GetDesiredStateRequest, GetReleaseManifestRequest,
        HeartbeatRequest, HeartbeatResponse, RegisterAgentRequest, RegisterAgentResponse,
        ReleaseManifestResponse, ReportApplyResultRequest, ReportUpgradeResultRequest,
        ReportUsageRequest,
        agent_control_server::{AgentControl, AgentControlServer},
    },
};
use cyberboard_database::{AgentHeartbeatInput, Database, DesiredConfigRecord};
use serde_json::Value;
use tonic::{Request, Response, Status};
use uuid::Uuid;

#[derive(Clone)]
pub struct AgentControlService {
    tenant_id: Uuid,
    database: Option<Arc<Database>>,
    sessions: Arc<RwLock<HashMap<String, Uuid>>>,
}

impl AgentControlService {
    pub fn new(tenant_id: Uuid, database: Option<Arc<Database>>) -> Self {
        Self {
            tenant_id,
            database,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn server(self) -> AgentControlServer<Self> {
        AgentControlServer::new(self)
    }

    fn remember(&self, agent_id: String, node_id: Uuid) -> Result<(), Status> {
        self.sessions
            .write()
            .map_err(|_| Status::internal("agent registry unavailable"))?
            .insert(agent_id, node_id);
        Ok(())
    }

    async fn authenticated(
        &self,
        agent_id: &str,
        node_id: Uuid,
        public_key: &str,
    ) -> Result<(), Status> {
        let in_memory = {
            let sessions = self
                .sessions
                .read()
                .map_err(|_| Status::internal("agent registry unavailable"))?;
            sessions.get(agent_id).copied() == Some(node_id)
        };
        if in_memory {
            Ok(())
        } else if let Some(database) = &self.database {
            if public_key.trim().is_empty() {
                return Err(Status::unauthenticated(
                    "agent public key is required for reconnect",
                ));
            }
            let known: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM nodes
                    WHERE tenant_id=$1 AND id=$2 AND agent_id=$3
                      AND agent_public_key=$4
                )",
            )
            .bind(self.tenant_id)
            .bind(node_id)
            .bind(agent_id)
            .bind(public_key)
            .fetch_one(database.pool())
            .await
            .map_err(|_| Status::internal("agent identity lookup failed"))?;
            if known {
                self.remember(agent_id.to_owned(), node_id)?;
                Ok(())
            } else {
                Err(Status::unauthenticated("agent identity is not registered"))
            }
        } else {
            Err(Status::unauthenticated("agent identity is not registered"))
        }
    }
}

#[tonic::async_trait]
impl AgentControl for AgentControlService {
    async fn register_agent(
        &self,
        request: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        let request = request.into_inner();
        if request.one_time_registration_token.trim().is_empty()
            || request.agent_public_key.trim().is_empty()
        {
            return Err(Status::invalid_argument(
                "registration token and public key are required",
            ));
        }
        let registration = if let Some(database) = &self.database {
            database
                .register_agent(
                    self.tenant_id,
                    &request.one_time_registration_token,
                    &request.agent_public_key,
                    &request.agent_version,
                    &request.platform,
                    &request.architecture,
                )
                .await
                .map_err(|_| Status::internal("agent registration failed"))?
                .ok_or_else(|| {
                    Status::permission_denied("registration token is invalid or already used")
                })?
        } else {
            let node_id = request
                .one_time_registration_token
                .split(':')
                .next()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| {
                    Status::permission_denied(
                        "development registration token must start with a node UUID",
                    )
                })?;
            cyberboard_database::AgentRegistrationRecord {
                node_id,
                agent_id: format!("agent-{}", Uuid::new_v4().simple()),
                agent_version: request.agent_version.clone(),
                platform: request.platform.clone(),
                architecture: request.architecture.clone(),
            }
        };
        self.remember(registration.agent_id.clone(), registration.node_id)?;
        Ok(Response::new(RegisterAgentResponse {
            agent_id: registration.agent_id,
            node_id: registration.node_id.to_string(),
            certificate_pem: String::new(),
            certificate_authority_pem: String::new(),
            certificate_expires_at: unix_now() + 3600,
            protocol_version: PROTOCOL_VERSION.to_owned(),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let request = request.into_inner();
        let node_id = Uuid::parse_str(&request.node_id)
            .map_err(|_| Status::invalid_argument("node_id is invalid"))?;
        self.authenticated(&request.agent_id, node_id, &request.agent_public_key)
            .await?;
        if let Some(database) = &self.database {
            let accepted = database
                .update_agent_heartbeat(
                    self.tenant_id,
                    &request.agent_id,
                    node_id,
                    &AgentHeartbeatInput {
                        agent_version: request.agent_version.clone(),
                        platform: request.platform.clone(),
                        architecture: request.architecture.clone(),
                        core_state: request.core_state.clone(),
                        memory_bytes: request.memory_bytes,
                        disk_free_bytes: request.disk_free_bytes,
                        cpu_percent: request.cpu_percent,
                    },
                )
                .await
                .map_err(|_| Status::internal("heartbeat persistence failed"))?;
            if !accepted {
                return Err(Status::permission_denied(
                    "agent identity is not registered",
                ));
            }
        }
        Ok(Response::new(HeartbeatResponse {
            desired_state_revision: request.current_config_revision,
            should_upgrade: false,
            protocol_version: PROTOCOL_VERSION.to_owned(),
        }))
    }

    async fn get_desired_state(
        &self,
        request: Request<GetDesiredStateRequest>,
    ) -> Result<Response<DesiredStateResponse>, Status> {
        let request = request.into_inner();
        let node_id = Uuid::parse_str(&request.node_id)
            .map_err(|_| Status::invalid_argument("node_id is invalid"))?;
        self.authenticated(&request.agent_id, node_id, &request.agent_public_key)
            .await?;
        let Some(database) = &self.database else {
            return Ok(Response::new(DesiredStateResponse::default()));
        };
        let Some(config) = database
            .desired_state_for_agent(self.tenant_id, &request.agent_id, node_id)
            .await
            .map_err(|_| Status::internal("desired state lookup failed"))?
        else {
            return Ok(Response::new(DesiredStateResponse::default()));
        };
        Ok(Response::new(desired_state(config)))
    }

    async fn report_apply_result(
        &self,
        request: Request<ReportApplyResultRequest>,
    ) -> Result<Response<Ack>, Status> {
        let request = request.into_inner();
        let node_id = Uuid::parse_str(&request.node_id)
            .map_err(|_| Status::invalid_argument("node_id is invalid"))?;
        let generation = request
            .generation
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("generation is invalid"))?;
        self.authenticated(&request.agent_id, node_id, &request.agent_public_key)
            .await?;
        let accepted = if let Some(database) = &self.database {
            database
                .record_agent_apply_result(
                    self.tenant_id,
                    &request.agent_id,
                    node_id,
                    generation,
                    &request.phase,
                    &request.error_code,
                    &request.error_message,
                )
                .await
                .map_err(|_| Status::internal("apply result persistence failed"))?
        } else {
            true
        };
        Ok(Response::new(Ack {
            request_id: Uuid::new_v4().to_string(),
            accepted,
        }))
    }

    async fn report_usage(
        &self,
        request: Request<ReportUsageRequest>,
    ) -> Result<Response<Ack>, Status> {
        let request = request.into_inner();
        let node_id = Uuid::parse_str(&request.node_id)
            .map_err(|_| Status::invalid_argument("node_id is invalid"))?;
        self.authenticated(&request.agent_id, node_id, &request.agent_public_key)
            .await?;
        if request.batch_id.trim().is_empty() || request.window_end <= request.window_start {
            return Err(Status::invalid_argument(
                "usage batch and window are required",
            ));
        }
        let payload: Value = if request.usage_payload.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_slice(&request.usage_payload)
                .map_err(|_| Status::invalid_argument("usage payload must be JSON"))?
        };
        if let Some(database) = &self.database {
            let _accepted = database
                .ingest_agent_usage(
                    self.tenant_id,
                    &request.agent_id,
                    node_id,
                    &request.batch_id,
                    request.sequence as i64,
                    request.window_start,
                    request.window_end,
                    &payload,
                )
                .await
                .map_err(|error| match error {
                    cyberboard_database::DatabaseError::InvalidUsagePayload(message) => {
                        Status::invalid_argument(message)
                    }
                    _ => Status::internal("usage receipt persistence failed"),
                })?;
        }
        Ok(Response::new(Ack {
            request_id: Uuid::new_v4().to_string(),
            accepted: true,
        }))
    }

    async fn get_release_manifest(
        &self,
        request: Request<GetReleaseManifestRequest>,
    ) -> Result<Response<ReleaseManifestResponse>, Status> {
        let request = request.into_inner();
        let node_id = Uuid::parse_str(&request.node_id)
            .map_err(|_| Status::invalid_argument("node_id is invalid"))?;
        self.authenticated(&request.agent_id, node_id, &request.agent_public_key)
            .await?;
        let Some(database) = &self.database else {
            return Ok(Response::new(ReleaseManifestResponse::default()));
        };
        let Some(release) = database
            .active_agent_release(self.tenant_id)
            .await
            .map_err(|_| Status::internal("release manifest lookup failed"))?
        else {
            return Ok(Response::new(ReleaseManifestResponse::default()));
        };
        Ok(Response::new(ReleaseManifestResponse {
            version: release.version,
            artifact_url: release.artifact_url,
            sha256: release.sha256,
            signature: release.signature,
            signing_key_id: release.signing_key_id,
            mandatory: release.mandatory,
        }))
    }

    async fn report_upgrade_result(
        &self,
        request: Request<ReportUpgradeResultRequest>,
    ) -> Result<Response<Ack>, Status> {
        let request = request.into_inner();
        let node_id = Uuid::parse_str(&request.node_id)
            .map_err(|_| Status::invalid_argument("node_id is invalid"))?;
        self.authenticated(&request.agent_id, node_id, &request.agent_public_key)
            .await?;
        if let Some(database) = &self.database {
            database
                .record_agent_upgrade_result(
                    self.tenant_id,
                    node_id,
                    &request.agent_id,
                    &request.target_version,
                    request.success,
                    (!request.error_code.is_empty()).then_some(request.error_code.as_str()),
                    (!request.error_message.is_empty()).then_some(request.error_message.as_str()),
                )
                .await
                .map_err(|_| Status::internal("upgrade result persistence failed"))?;
        }
        Ok(Response::new(Ack {
            request_id: Uuid::new_v4().to_string(),
            accepted: true,
        }))
    }
}

fn desired_state(config: DesiredConfigRecord) -> DesiredStateResponse {
    let signed_config = if config.signature.trim_start().starts_with('{') {
        config.signature.as_bytes().to_vec()
    } else {
        Vec::new()
    };
    DesiredStateResponse {
        generation: config.generation.to_string(),
        core_type: config.core_type,
        core_version: config.core_version,
        signed_config,
        content_hash: config.content_hash,
        signature: config.signature,
        signing_key_id: String::new(),
        expires_at: unix_now() + 300,
        expected_previous_hash: config.expected_previous_hash,
        generation_number: config.generation.max(0) as u64,
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn registered() -> (AgentControlService, Uuid, String) {
        let service = AgentControlService::new(Uuid::from_u128(1), None);
        let node_id = Uuid::from_u128(2);
        let response = service
            .register_agent(Request::new(RegisterAgentRequest {
                one_time_registration_token: format!("{node_id}:secret"),
                agent_public_key: "test-public-key".to_owned(),
                agent_version: "test".to_owned(),
                platform: "test".to_owned(),
                architecture: "test".to_owned(),
                unix_time: unix_now(),
                nonce: "nonce".to_owned(),
            }))
            .await
            .unwrap()
            .into_inner();
        (service, node_id, response.agent_id)
    }

    #[tokio::test]
    async fn registration_remembers_agent_identity() {
        let (service, node_id, agent_id) = registered().await;
        assert!(
            service
                .authenticated(&agent_id, node_id, "test-public-key")
                .await
                .is_ok()
        );
        assert!(
            service
                .authenticated(&agent_id, Uuid::from_u128(3), "test-public-key")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn desired_state_is_empty_until_a_signed_database_revision_exists() {
        let (service, node_id, agent_id) = registered().await;
        let response = service
            .get_desired_state(Request::new(GetDesiredStateRequest {
                agent_id,
                node_id: node_id.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.signed_config.is_empty());
        assert_eq!(response.generation, "");
    }

    #[tokio::test]
    async fn usage_rejects_invalid_window() {
        let (service, node_id, agent_id) = registered().await;
        let error = service
            .report_usage(Request::new(ReportUsageRequest {
                agent_id,
                node_id: node_id.to_string(),
                batch_id: "batch".to_owned(),
                window_start: 10,
                window_end: 10,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn release_manifest_is_explicitly_empty_when_unconfigured() {
        let (service, node_id, agent_id) = registered().await;
        let response = service
            .get_release_manifest(Request::new(GetReleaseManifestRequest {
                agent_id,
                node_id: node_id.to_string(),
                current_agent_version: "0.1.0".to_owned(),
                agent_public_key: "test-public-key".to_owned(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.version.is_empty());
        assert!(response.artifact_url.is_empty());
        assert!(!response.mandatory);
    }
}
