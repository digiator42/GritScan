mod api;
mod db;
mod mcp;
mod middleware;
mod scanner;
mod state;
mod types;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use gritshield::core::logger::LogLevel;
use gritshield::database::db::{DbConfig, DbManager};
use gritshield::prelude::*;

use crate::middleware::{ApiKeyMiddleware, BodyLimitMiddleware, HttpSecurityMiddleware};
use crate::state::AppState;
use crate::types::ScanConfig;

#[tokio::main]
async fn main() {
    // --- Persistence: file-backed SQLite via the framework's DbManager ---
    let db_url = std::env::var("GS_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://gritscan.db?mode=rwc".to_string());
    let db_config = DbConfig {
        url: db_url.clone(),
        max_connections: 5,
        min_connections: 1,
        connect_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(300),
    };

    let shared_db = DbManager::connect(db_config)
        .await
        .unwrap_or_else(|e| panic!("failed to connect to database at {db_url}: {e}"));

    db::init_tables(shared_db.as_ref())
        .await
        .expect("failed to initialize GritScan schema");

    // --- Scan configuration ---
    let config = db::get_config(shared_db.as_ref())
        .await
        .unwrap_or(ScanConfig {
            target_timeout_ms: 5000,
            port_timeout_ms: 2000,
            max_ports_per_host: 1000,
            compliance_check: true,
            auto_alert: true,
            alert_severity_threshold: "high".to_string(),
        });

    // --- GritIRT connector ---
    let irt_url = std::env::var("GS_IRT_URL").ok().filter(|s| !s.is_empty());
    let irt_api_key = std::env::var("GS_IRT_API_KEY").ok().filter(|s| !s.is_empty());

    let api_key = std::env::var("GS_API_KEY").ok().filter(|k| !k.is_empty());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("failed to build outbound HTTP client");

    let app_state = Arc::new(AppState {
        db: shared_db.clone(),
        api_key,
        irt_url: irt_url.clone(),
        irt_api_key,
        client,
        config,
        active_scans: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
    });
    gritshield::core::ioc::AutoWire::component((*app_state).clone());

    // --- Router with the GritScan middleware chain ---
    let router = Router::new()
        .mount_logger(LogLevel::Debug)
        .mount_db(shared_db)
        .add_middleware(gritshield::middleware::CorsMiddleware::new(vec![
            "*".to_string(),
        ]))
        .add_middleware(ApiKeyMiddleware::new(app_state.clone()))
        .add_middleware(BodyLimitMiddleware::new(1024 * 1024)) // 1 MiB
        .add_middleware(HttpSecurityMiddleware::new())
        .route(("/health", HttpMethod::GET, api::health))
        // Targets
        .route(("/api/v1/targets", HttpMethod::POST, api::create_target))
        .route(("/api/v1/targets", HttpMethod::GET, api::list_targets))
        .route(("/api/v1/targets/:id", HttpMethod::DELETE, api::delete_target))
        // Scans
        .route(("/api/v1/scans", HttpMethod::POST, api::start_scan))
        .route(("/api/v1/scans", HttpMethod::GET, api::list_scans))
        .route(("/api/v1/scans/:id", HttpMethod::GET, api::get_scan))
        // Vulnerabilities
        .route(("/api/v1/vulnerabilities", HttpMethod::GET, api::list_vulnerabilities))
        .route(("/api/v1/vulnerabilities/stats", HttpMethod::GET, api::vuln_stats))
        .route(("/api/v1/vulnerabilities/:id", HttpMethod::GET, api::get_vulnerability))
        .route(("/api/v1/vulnerabilities/:id/status", HttpMethod::POST, api::update_vuln_status))
        // Attack surface
        .route(("/api/v1/attack-surface", HttpMethod::GET, api::attack_surface))
        // Compliance
        .route(("/api/v1/compliance/rules", HttpMethod::GET, api::list_compliance_rules))
        // Config
        .route(("/api/v1/config", HttpMethod::GET, api::get_config))
        .route(("/api/v1/config", HttpMethod::POST, api::update_config))
        // SSE
        .route(("/api/v1/stream", HttpMethod::GET, api::stream));

    let host = std::env::var("GS_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("GS_PORT").unwrap_or_else(|_| "8050".to_string());

    println!("[gritscan] attack surface scanner listening on http://{host}:{port}");
    println!(
        "[gritscan] MCP surface mounted automatically at http://{host}:{port}/mcp (MCP_HTTP_PREFIX to relocate)"
    );
    println!(
        "[gritscan] database: {}",
        if db_url.contains("memory") { db_url } else { format!("{db_url} (file)") }
    );
    if let Some(url) = &irt_url {
        println!("[gritscan] GritIRT connector: {url}");
    } else {
        println!("[gritscan] GritIRT connector: not configured (set GS_IRT_URL)");
    }

    ignite(&host, &port, router).await;
}
