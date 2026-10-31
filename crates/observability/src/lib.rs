//! Shared tracing setup for all Cyberboard processes.

use tracing_subscriber::{EnvFilter, fmt};

pub fn init(service_name: &str) {
    let default_filter = format!("{service_name}=info,info");
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .try_init();
}
