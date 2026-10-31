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

#[cfg(test)]
mod tests {
    use super::{
        FIFTH_MIGRATION, FOURTH_MIGRATION, INITIAL_MIGRATION, INITIAL_MIGRATION_NAME,
        SECOND_MIGRATION, SECOND_MIGRATION_NAME, SIXTH_MIGRATION, THIRD_MIGRATION,
        THIRD_MIGRATION_NAME,
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
    }
}
