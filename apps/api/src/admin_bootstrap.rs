use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use cyberboard_config::ApiConfig;
use cyberboard_database::Database;
use tracing::info;

pub async fn run(
    database: &Database,
    config: &ApiConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some((email, password)) = config.bootstrap_admin.as_ref() {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| "failed to hash bootstrap admin password")?
            .to_string();
        match database
            .bootstrap_admin(config.tenant_id, email, &password_hash)
            .await?
        {
            Some(user_id) => info!(%email, %user_id, "bootstrapped initial tenant administrator"),
            None => {
                info!(%email, "admin bootstrap skipped because tenant already has an administrator")
            }
        }
    } else if !database.tenant_has_admin(config.tenant_id).await? {
        info!(tenant_id = %config.tenant_id, "tenant has no administrator; configure CYBERBOARD_BOOTSTRAP_ADMIN_EMAIL and CYBERBOARD_BOOTSTRAP_ADMIN_PASSWORD to bootstrap one");
    }
    Ok(())
}
