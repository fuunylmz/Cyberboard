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
