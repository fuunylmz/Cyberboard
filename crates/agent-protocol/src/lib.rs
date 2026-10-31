//! Versioned control-plane/agent protocol contract.
//!
//! The `.proto` file is deliberately kept as a source artifact in the first
//! skeleton. Code generation will be enabled once the transport implementation
//! is introduced, so the initial workspace does not require a system `protoc`.

pub const PROTOCOL_PACKAGE: &str = "cyberboard.agent.v1";
pub const PROTOCOL_VERSION: &str = "v1";
pub const PROTOCOL_SCHEMA: &str = include_str!("../proto/agent.proto");

#[cfg(test)]
mod tests {
    use super::{PROTOCOL_PACKAGE, PROTOCOL_SCHEMA, PROTOCOL_VERSION};

    #[test]
    fn protocol_artifact_is_versioned() {
        assert_eq!(PROTOCOL_VERSION, "v1");
        assert!(PROTOCOL_SCHEMA.contains("service AgentControl"));
        assert!(PROTOCOL_PACKAGE.contains("cyberboard.agent"));
    }
}
