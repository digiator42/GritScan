use serde::{Deserialize, Serialize};

/// Current clock as integer epoch milliseconds.
pub fn now_ms_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Current clock as fractional epoch milliseconds.
pub fn now_ms_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0)
}

/// Canonical severity levels.
pub fn normalize_severity(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical".to_string(),
        "high" => "high".to_string(),
        "medium" => "medium".to_string(),
        "low" => "low".to_string(),
        _ => "medium".to_string(),
    }
}

/// Severity rank for comparisons.
pub fn severity_rank(sev: &str) -> u8 {
    match normalize_severity(sev).as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Scan target: a host or subnet to scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: i64,
    pub name: String,
    pub cidr: String,
    pub ports: Vec<u16>,
    pub enabled: bool,
    pub created_at: i64,
}

/// A single open port finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortFinding {
    pub port: u16,
    pub service: String,
    pub version: String,
    pub state: String, // "open" | "filtered" | "closed"
}

/// A vulnerability detected during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: i64,
    pub scan_id: i64,
    pub target_id: i64,
    pub target_name: String,
    pub host: String,
    pub port: u16,
    pub service: String,
    pub vuln_type: String, // "open_port" | "unpatched_service" | "weak_ssl" | "default_creds" | "compliance"
    pub severity: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub cve: Option<String>,
    pub cvss: Option<f64>,
    pub status: String, // "open" | "acknowledged" | "remediated" | "false_positive"
    pub first_seen_ms: f64,
    pub last_seen_ms: f64,
    pub alert_sent: bool,
    pub created_at: i64,
}

/// A scan run record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: i64,
    pub target_id: i64,
    pub target_name: String,
    pub status: String, // "pending" | "running" | "completed" | "failed"
    pub hosts_scanned: i64,
    pub hosts_up: i64,
    pub ports_found: i64,
    pub vulns_found: i64,
    pub started_at: i64,
    pub finished_at: i64,
    pub duration_ms: i64,
    pub error: String,
}

/// Alert payload sent to GritIRT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrtAlert {
    pub source: String,
    pub kind: String,
    pub severity: String,
    pub entity: String,
    pub detail: serde_json::Value,
    pub ts_ms: f64,
    pub correlation_key: Option<String>,
}

/// Compliance rule for configuration checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRule {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub port: u16,
    pub allowed: bool, // true = port should be open, false = should be closed
    pub severity: String,
    pub enabled: bool,
}

/// Scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target_timeout_ms: u64,
    pub port_timeout_ms: u64,
    pub max_ports_per_host: u32,
    pub compliance_check: bool,
    pub auto_alert: bool,
    pub alert_severity_threshold: String, // minimum severity to auto-alert
}
