#![allow(clippy::result_large_err)]

use std::{fs, time::Duration};

use cyberboard_agent_protocol::generated::{
    DesiredStateResponse, GetDesiredStateRequest, GetReleaseManifestRequest, HeartbeatRequest,
    RegisterAgentRequest, ReleaseManifestResponse, ReportApplyResultRequest,
    ReportUpgradeResultRequest, agent_control_client::AgentControlClient,
};
use cyberboard_config::AgentConfig;
use tonic::{
    Request, Status,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};

pub struct TonicAgentTransport {
    client: AgentControlClient<Channel>,
}

impl TonicAgentTransport {
    pub async fn connect_with_backoff(
        config: &AgentConfig,
        attempts: u32,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut delay = Duration::from_millis(250);
        let mut last = None;
        for _ in 0..attempts.max(1) {
            match Self::connect(config).await {
                Ok(client) => return Ok(client),
                Err(error) => {
                    last = Some(error);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(10));
                }
            }
        }
        Err(last.unwrap_or_else(|| "transport connection failed".into()))
    }
    pub async fn connect(
        config: &AgentConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if config.control_plane_url.starts_with("http://") && !config.insecure {
            return Err("cleartext AgentControl requires CYBERBOARD_AGENT_INSECURE=1".into());
        }
        let mut endpoint = Endpoint::from_shared(config.control_plane_url.clone())?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        if let (Some(ca), Some(cert), Some(key)) = (
            &config.ca_cert_path,
            &config.client_cert_path,
            &config.client_key_path,
        ) {
            let ca = Certificate::from_pem(fs::read(ca)?);
            let identity = Identity::from_pem(fs::read(cert)?, fs::read(key)?);
            let mut tls = ClientTlsConfig::new().ca_certificate(ca).identity(identity);
            if let Some(name) = &config.tls_server_name {
                tls = tls.domain_name(name);
            }
            endpoint = endpoint.tls_config(tls)?;
        }
        let channel = endpoint.connect().await?;
        Ok(Self {
            client: AgentControlClient::new(channel),
        })
    }

    pub async fn heartbeat_response(
        &mut self,
        request: HeartbeatRequest,
    ) -> Result<cyberboard_agent_protocol::generated::HeartbeatResponse, Status> {
        Ok(self
            .client
            .heartbeat(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn register(&mut self, request: RegisterAgentRequest) -> Result<String, Status> {
        Ok(self
            .client
            .register_agent(Request::new(request))
            .await?
            .into_inner()
            .agent_id)
    }

    pub async fn desired_state(
        &mut self,
        request: GetDesiredStateRequest,
    ) -> Result<DesiredStateResponse, Status> {
        Ok(self
            .client
            .get_desired_state(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn report_apply(&mut self, request: ReportApplyResultRequest) -> Result<(), Status> {
        self.client
            .report_apply_result(Request::new(request))
            .await
            .map(|_| ())
    }

    pub async fn release_manifest(
        &mut self,
        request: GetReleaseManifestRequest,
    ) -> Result<ReleaseManifestResponse, Status> {
        Ok(self
            .client
            .get_release_manifest(Request::new(request))
            .await?
            .into_inner())
    }

    pub async fn report_upgrade(
        &mut self,
        request: ReportUpgradeResultRequest,
    ) -> Result<(), Status> {
        self.client
            .report_upgrade_result(Request::new(request))
            .await
            .map(|_| ())
    }
}
