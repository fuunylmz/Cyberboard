pub struct ConfigPublishInput<'a> {
    pub tenant_id: Uuid,
    pub revision_id: Uuid,
    pub expected_generation: i64,
    pub expected_previous_hash: Option<&'a str>,
    pub signed_envelope: &'a str,
    pub actor_user_id: Uuid,
}

pub struct ConfigRollbackInput<'a> {
    pub tenant_id: Uuid,
    pub revision_id: Uuid,
    pub expected_generation: i64,
    pub actor_user_id: Uuid,
    pub reason: Option<&'a str>,
    pub sign: &'a (dyn Fn(Uuid, u64, Vec<u8>) -> String + Send + Sync),
}

pub struct SessionWithRefreshInput<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub access_token: &'a str,
    pub refresh_token: &'a str,
    pub role: &'a str,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
}

pub struct ConfigRevisionCreateInput<'a> {
    pub tenant_id: Uuid,
    pub template_id: Uuid,
    pub node_id: Uuid,
    pub generation: i64,
    pub core_version: &'a str,
    pub payload: &'a serde_json::Value,
    pub content_hash: &'a str,
}

pub struct AgentUsageInput<'a> {
    pub tenant_id: Uuid,
    pub agent_id: &'a str,
    pub node_id: Uuid,
    pub batch_id: &'a str,
    pub sequence: i64,
    pub window_start: i64,
    pub window_end: i64,
    pub payload: &'a serde_json::Value,
}

pub struct AgentUpgradeResultInput<'a> {
    pub tenant_id: Uuid,
    pub node_id: Uuid,
    pub agent_id: &'a str,
    pub target_version: &'a str,
    pub success: bool,
    pub error_code: Option<&'a str>,
    pub error_message: Option<&'a str>,
}

pub struct AgentApplyResultInput<'a> {
    pub tenant_id: Uuid,
    pub agent_id: &'a str,
    pub node_id: Uuid,
    pub generation: i64,
    pub phase: &'a str,
    pub error_code: &'a str,
    pub error_message: &'a str,
    pub previous_hash: &'a str,
    pub applied_hash: &'a str,
    pub retry_count: i32,
}
