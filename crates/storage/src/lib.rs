//! Storage boundary for the first reviewable database contract.
//!
//! This crate intentionally does not connect to PostgreSQL yet. Keeping the
//! migration as a compile-time resource gives API, worker, and review tooling a
//! stable contract before SQLx or a connection pool is introduced.

pub const INITIAL_MIGRATION_NAME: &str = "0001_initial.sql";
pub const INITIAL_MIGRATION: &str = include_str!("../../../deploy/migrations/0001_initial.sql");
pub const SECOND_MIGRATION_NAME: &str = "0002_resource_fields.sql";
pub const SECOND_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0002_resource_fields.sql");
pub const THIRD_MIGRATION_NAME: &str = "0003_control_plane_resources.sql";
pub const THIRD_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0003_control_plane_resources.sql");
pub const FOURTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0004_config_revision_fields.sql");
pub const FIFTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0005_subscription_nodes.sql");
pub const SIXTH_MIGRATION: &str = include_str!("../../../deploy/migrations/0006_sessions.sql");
pub const SEVENTH_MIGRATION_NAME: &str = "0007_payment_fields.sql";
pub const SEVENTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0007_payment_fields.sql");
pub const EIGHTH_MIGRATION_NAME: &str = "0008_agent_control.sql";
pub const EIGHTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0008_agent_control.sql");
pub const NINTH_MIGRATION_NAME: &str = "0009_agent_registration_token_lifecycle.sql";
pub const NINTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0009_agent_registration_token_lifecycle.sql");
pub const TENTH_MIGRATION_NAME: &str = "0010_subscription_token_lifecycle.sql";
pub const TENTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0010_subscription_token_lifecycle.sql");
pub const ELEVENTH_MIGRATION_NAME: &str = "0011_agent_releases.sql";
pub const ELEVENTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0011_agent_releases.sql");
pub const TWELFTH_MIGRATION_NAME: &str = "0012_session_refresh.sql";
pub const TWELFTH_MIGRATION: &str =
    include_str!("../../../deploy/migrations/0012_session_refresh.sql");

#[cfg(test)]
mod tests {
    use super::{
        EIGHTH_MIGRATION, EIGHTH_MIGRATION_NAME, ELEVENTH_MIGRATION, ELEVENTH_MIGRATION_NAME,
        FIFTH_MIGRATION, FOURTH_MIGRATION, INITIAL_MIGRATION, INITIAL_MIGRATION_NAME,
        NINTH_MIGRATION, NINTH_MIGRATION_NAME, SECOND_MIGRATION, SECOND_MIGRATION_NAME,
        SEVENTH_MIGRATION, SEVENTH_MIGRATION_NAME, SIXTH_MIGRATION, TENTH_MIGRATION,
        TENTH_MIGRATION_NAME, THIRD_MIGRATION, THIRD_MIGRATION_NAME, TWELFTH_MIGRATION,
        TWELFTH_MIGRATION_NAME,
    };

    #[test]
    fn initial_migration_is_embedded_and_covers_core_tables() {
        assert_eq!(INITIAL_MIGRATION_NAME, "0001_initial.sql");
        for table in [
            "tenants",
            "users",
            "roles",
            "user_roles",
            "plans",
            "subscriptions",
            "nodes",
            "config_revisions",
            "usage_events",
            "usage_buckets",
            "audit_logs",
        ] {
            assert!(
                INITIAL_MIGRATION.contains(&format!("CREATE TABLE {table}")),
                "missing table {table}"
            );
        }
    }

    #[test]
    fn append_only_tables_have_mutation_guards() {
        assert!(INITIAL_MIGRATION.contains("usage_events_append_only"));
        assert!(INITIAL_MIGRATION.contains("audit_logs_append_only"));
        assert!(INITIAL_MIGRATION.contains("RAISE EXCEPTION"));
    }

    #[test]
    fn second_migration_contains_resource_fields() {
        assert_eq!(SECOND_MIGRATION_NAME, "0002_resource_fields.sql");
        for field in [
            "description",
            "price_cents",
            "device_limit",
            "node_group_ids",
            "port",
            "tags",
        ] {
            assert!(SECOND_MIGRATION.contains(field), "missing field {field}");
        }
    }

    #[test]
    fn third_migration_contains_control_plane_tables() {
        assert_eq!(THIRD_MIGRATION_NAME, "0003_control_plane_resources.sql");
        for table in [
            "config_templates",
            "config_deployments",
            "orders",
            "payments",
            "devices",
        ] {
            assert!(
                THIRD_MIGRATION.contains(&format!("CREATE TABLE {table}")),
                "missing table {table}"
            );
        }
    }

    #[test]
    fn fourth_migration_contains_revision_contract() {
        assert!(FOURTH_MIGRATION.contains("publish_status"));
        assert!(FOURTH_MIGRATION.contains("validation_status"));
        assert!(FOURTH_MIGRATION.contains("template_id"));
        assert!(FOURTH_MIGRATION.contains("updated_by"));
        assert!(FIFTH_MIGRATION.contains("subscription_nodes"));
        assert!(SIXTH_MIGRATION.contains("token_hash"));
        assert_eq!(SEVENTH_MIGRATION_NAME, "0007_payment_fields.sql");
        assert!(SEVENTH_MIGRATION.contains("provider_event_id"));
        assert!(SEVENTH_MIGRATION.contains("idempotency_key"));
        assert_eq!(EIGHTH_MIGRATION_NAME, "0008_agent_control.sql");
        assert!(EIGHTH_MIGRATION.contains("agent_usage_receipts"));
        assert!(EIGHTH_MIGRATION.contains("agent_registration_token_hash"));
        assert_eq!(
            NINTH_MIGRATION_NAME,
            "0009_agent_registration_token_lifecycle.sql"
        );
        assert!(NINTH_MIGRATION.contains("agent_registration_token_expires_at"));
        assert_eq!(
            TENTH_MIGRATION_NAME,
            "0010_subscription_token_lifecycle.sql"
        );
        assert!(TENTH_MIGRATION.contains("subscription_token_hash"));
        assert_eq!(ELEVENTH_MIGRATION_NAME, "0011_agent_releases.sql");
        assert!(ELEVENTH_MIGRATION.contains("agent_releases"));
        assert!(ELEVENTH_MIGRATION.contains("agent_upgrade_results"));
        assert_eq!(TWELFTH_MIGRATION_NAME, "0012_session_refresh.sql");
        assert!(TWELFTH_MIGRATION.contains("refresh_token_hash"));
    }
}
