//! GritScan backend API contract (see `docs/api.md`).
//!
//! All endpoints are JSON. When the backend has `GS_API_KEY` set, every
//! request must present the key via the `X-API-Key` header (or `?api_key=`,
//! which is what the SSE `EventSource` falls back to since it can't set
//! headers). An empty key means the backend is open — no header is sent.

// Reply structs mirror the full wire contract; some fields are decoded for
// completeness but not rendered, which is intentional.
#![allow(dead_code)]

use serde::Deserialize;

use crate::state::{
    AppState, ComplianceRule, ScanConfig, ScanRun, ScanTarget, Vulnerability, VulnStats,
};

/// Backend base URL. Empty means same-origin.
pub const BASE_URL: &str = "http://127.0.0.1:8050";

pub const HEALTH_PATH: &str = "/health";
pub const TARGETS_PATH: &str = "/api/v1/targets";
pub const SCANS_PATH: &str = "/api/v1/scans";
pub const VULNS_PATH: &str = "/api/v1/vulnerabilities";
pub const VULN_STATS_PATH: &str = "/api/v1/vulnerabilities/stats";
pub const ATTACK_SURFACE_PATH: &str = "/api/v1/attack-surface";
pub const COMPLIANCE_PATH: &str = "/api/v1/compliance/rules";
pub const CONFIG_PATH: &str = "/api/v1/config";
pub const STREAM_PATH: &str = "/api/v1/stream";

fn with_base(path: &str) -> String {
    if BASE_URL.is_empty() {
        path.to_string()
    } else {
        format!("{}{}", BASE_URL.trim_end_matches('/'), path)
    }
}

/// Attach the in-memory API key as `X-API-Key` when one is set.
fn authed(app: &AppState, path: &str) -> veloasm::RequestBuilder {
    let mut b = veloasm::request(&with_base(path));
    let key = app.api_key.get();
    if !key.trim().is_empty() {
        b = b.header("X-API-Key", key.trim());
    }
    b
}

/// Stream URL with `?api_key=` appended when a key is set (EventSource
/// cannot send headers).
pub fn stream_url(app: &AppState) -> String {
    let key = app.api_key.get();
    let base = with_base(STREAM_PATH);
    if key.trim().is_empty() {
        base
    } else {
        format!("{base}?api_key={}", key.trim())
    }
}

/// Fetch failure with the HTTP status preserved.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn is_unauthorized(&self) -> bool {
        self.status == 401 || self.status == 403
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<veloasm::FetchError> for ApiError {
    fn from(e: veloasm::FetchError) -> Self {
        match e {
            veloasm::FetchError::Status { code, reason } => ApiError {
                status: code,
                message: if code == 401 {
                    "unauthorized: missing or bad API key".to_string()
                } else if code == 403 {
                    "forbidden: your API key cannot perform this action".to_string()
                } else if code == 409 {
                    "conflict: a scan is already running for this target".to_string()
                } else {
                    format!("request failed ({code} {reason})")
                },
            },
            veloasm::FetchError::Network(msg) => ApiError { status: 0, message: msg },
            veloasm::FetchError::Decode(msg) => ApiError { status: 0, message: msg },
        }
    }
}

// ---------------------------------------------------------------------------
// Typed replies
//
// These mirror the full API contract from docs/api.md. Some fields (counts,
// ids echoed back) are decoded for completeness but not rendered; that's
// intentional — they document the wire shape.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HealthReply {
    pub service: String,
    pub status: String,
    pub db: bool,
    pub vulnerability_stats: VulnStats,
    pub irt_connected: bool,
}

#[derive(Debug, Deserialize)]
pub struct TargetsReply {
    pub count: i64,
    pub targets: Vec<ScanTarget>,
}

#[derive(Debug, Deserialize)]
pub struct TargetReply {
    pub target_id: i64,
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteReply {
    pub deleted: bool,
    pub target_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ScansReply {
    pub count: i64,
    pub scans: Vec<ScanRun>,
}

#[derive(Debug, Deserialize)]
pub struct StartScanReply {
    pub scan_id: i64,
    pub target_id: i64,
    pub target_name: String,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct VulnsReply {
    pub count: i64,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
pub struct VulnReply {
    pub vulnerability: Vulnerability,
}

#[derive(Debug, Deserialize)]
pub struct AttackSurfaceReply {
    pub targets: i64,
    pub open_vulnerabilities: i64,
    pub by_service: std::collections::BTreeMap<String, i64>,
    pub by_severity: crate::state::SeverityCounts,
}

#[derive(Debug, Deserialize)]
pub struct ComplianceReply {
    pub count: i64,
    pub rules: Vec<ComplianceRule>,
}

// ---------------------------------------------------------------------------
// Calls
//
// The published `veloasm` 0.1.1 `RequestBuilder` has no `send_json`; this
// local shim reproduces it — send, read the body text, decode with serde_json.
// ---------------------------------------------------------------------------

async fn send_json<T>(builder: veloasm::RequestBuilder) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned,
{
    let resp = builder.send().await.map_err(ApiError::from)?;
    let text = resp.text().await.map_err(|e| ApiError {
        status: 0,
        message: e
            .as_string()
            .unwrap_or_else(|| "failed to read response body".to_string()),
    })?;
    serde_json::from_str::<T>(&text).map_err(|e| ApiError {
        status: 0,
        message: format!("decode error: {e}"),
    })
}

pub async fn health(app: &AppState) -> Result<HealthReply, ApiError> {
    send_json(authed(app, HEALTH_PATH)).await
}

pub async fn list_targets(app: &AppState) -> Result<TargetsReply, ApiError> {
    send_json(authed(app, TARGETS_PATH)).await
}

pub async fn add_target(
    app: &AppState,
    name: &str,
    cidr: &str,
    ports: Vec<u16>,
) -> Result<TargetReply, ApiError> {
    let body = serde_json::json!({ "name": name, "cidr": cidr, "ports": ports });
    send_json(authed(app, TARGETS_PATH).method("POST").json_body(&body)?).await
}

pub async fn delete_target(app: &AppState, id: i64) -> Result<DeleteReply, ApiError> {
    send_json(authed(app, &format!("{TARGETS_PATH}/{id}")).method("DELETE")).await
}

pub async fn list_scans(app: &AppState, limit: u32) -> Result<ScansReply, ApiError> {
    send_json(authed(app, SCANS_PATH).query("limit", &limit.to_string())).await
}

pub async fn start_scan(app: &AppState, target_id: i64) -> Result<StartScanReply, ApiError> {
    let body = serde_json::json!({ "target_id": target_id });
    send_json(authed(app, SCANS_PATH).method("POST").json_body(&body)?).await
}

pub async fn list_vulns(
    app: &AppState,
    status: &str,
    severity: &str,
    limit: u32,
) -> Result<VulnsReply, ApiError> {
    let mut b = authed(app, VULNS_PATH).query("limit", &limit.to_string());
    if status != "all" {
        b = b.query("status", status);
    }
    if severity != "all" {
        b = b.query("severity", severity);
    }
    send_json(b).await
}

pub async fn vuln_stats(app: &AppState) -> Result<VulnStats, ApiError> {
    send_json(authed(app, VULN_STATS_PATH)).await
}

pub async fn get_vuln(app: &AppState, id: i64) -> Result<VulnReply, ApiError> {
    send_json(authed(app, &format!("{VULNS_PATH}/{id}"))).await
}

pub async fn update_vuln_status(
    app: &AppState,
    id: i64,
    status: &str,
) -> Result<VulnReply, ApiError> {
    let body = serde_json::json!({ "status": status });
    send_json(
        authed(app, &format!("{VULNS_PATH}/{id}/status"))
            .method("POST")
            .json_body(&body)?,
    )
    .await
}

pub async fn attack_surface(app: &AppState) -> Result<AttackSurfaceReply, ApiError> {
    send_json(authed(app, ATTACK_SURFACE_PATH)).await
}

pub async fn compliance_rules(app: &AppState) -> Result<ComplianceReply, ApiError> {
    send_json(authed(app, COMPLIANCE_PATH)).await
}

pub async fn get_config(app: &AppState) -> Result<ScanConfig, ApiError> {
    send_json(authed(app, CONFIG_PATH)).await
}

pub async fn update_config(app: &AppState, cfg: &ScanConfig) -> Result<ScanConfig, ApiError> {
    send_json(authed(app, CONFIG_PATH).method("POST").json_body(cfg)?).await
}
