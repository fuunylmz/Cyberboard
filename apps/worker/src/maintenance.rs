use cyberboard_database::{Database, DatabaseResult, UsageMaintenanceStats};
use uuid::Uuid;

/// Executes one idempotent maintenance pass for a tenant.
pub async fn run_once(
    database: &Database,
    tenant_id: Uuid,
) -> DatabaseResult<UsageMaintenanceStats> {
    database.run_usage_maintenance(tenant_id).await
}

#[cfg(test)]
mod tests {
    use super::UsageMaintenanceStats;

    #[test]
    fn a_new_pass_starts_with_zero_work() {
        assert_eq!(UsageMaintenanceStats::default().buckets_upserted, 0);
        assert_eq!(UsageMaintenanceStats::default().subscriptions_expired, 0);
    }
}
