use std::collections::HashSet;
use std::sync::Arc;
use sea_orm::DatabaseConnection;
use tokio::sync::Mutex;

use crate::types::ScanConfig;

/// Application-wide shared state.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DatabaseConnection>,
    /// When `Some`, requests must present `X-API-Key` (or `?api_key=`).
    pub api_key: Option<String>,
    /// Base URL of the GritIRT backend for alert forwarding.
    pub irt_url: Option<String>,
    /// API key for GritIRT.
    pub irt_api_key: Option<String>,
    /// Reusable outbound HTTP client.
    pub client: reqwest::Client,
    /// Scan configuration.
    pub config: ScanConfig,
    /// IDs of scans currently running (prevents duplicate runs).
    pub active_scans: Arc<Mutex<HashSet<i64>>>,
}

/// Resolve the registered application state from the global container.
pub fn resolve() -> Arc<AppState> {
    use gritshield::core::ioc::CONTEXT;
    CONTEXT
        .resolve::<AppState>()
        .expect("AppState was not registered; this must be the first boot step")
}
