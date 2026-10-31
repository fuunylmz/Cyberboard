//! Storage boundary for the first reviewable database contract.
//!
//! This crate intentionally does not connect to PostgreSQL yet. Keeping the
//! migration as a compile-time resource gives API, worker, and review tooling a
//! stable contract before SQLx or a connection pool is introduced.

pub const INITIAL_MIGRATION_NAME: &str = "0001_initial.sql";
pub const INITIAL_MIGRATION: &str = include_str!("../../../deploy/migrations/0001_initial.sql");

#[cfg(test)]
mod tests {
    use super::{INITIAL_MIGRATION, INITIAL_MIGRATION_NAME};

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
}
