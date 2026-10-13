//! Reactive application state for the GritScan console.
//!
//! One [`AppState`] value holds every signal, provided once via `provide!`
//! and pulled out of context with `use_context::<AppState>()`.
//!
//! Auth is an API key held in memory only (never localStorage) — matching the
//! GritScan backend's optional `X-API-Key` / `?api_key=` scheme. When no key
//! is configured the backend is open, so an empty key means "no auth bar".

use std::cell::Cell;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use veloasm::prelude::*;

// ---------------------------------------------------------------------------
// Severity / status helpers (full Tailwind class literals live here so the
// scanner sees them — never build class names dynamically).
// ---------------------------------------------------------------------------

pub const STATUSES: [&str; 4] = ["open", "acknowledged", "remediated", "false_positive"];

/// Tailwind text color for a severity level (used on badges / table cells).
pub fn severity_text(sev: &str) -> &'static str {
    match sev {
        "critical" => "text-rose-400",
        "high" => "text-orange-400",
        "medium" => "text-amber-400",
        _ => "text-sky-400",
    }
}

/// Tailwind badge (bg + text) for a severity level.
pub fn severity_badge(sev: &str) -> &'static str {
    match sev {
        "critical" => "bg-rose-500/15 text-rose-400 border border-rose-500/30",
        "high" => "bg-orange-500/15 text-orange-400 border border-orange-500/30",
        "medium" => "bg-amber-500/15 text-amber-400 border border-amber-500/30",
        _ => "bg-sky-500/15 text-sky-400 border border-sky-500/30",
    }
}

/// Colored left-edge bar for a severity (vuln list rows).
pub fn severity_bar(sev: &str) -> &'static str {
    match sev {
        "critical" => "bg-rose-500",
        "high" => "bg-orange-500",
        "medium" => "bg-amber-500",
        _ => "bg-sky-500",
    }
}

/// Tailwind badge for a vulnerability status.
pub fn status_badge(status: &str) -> &'static str {
    match status {
        "open" => "bg-rose-500/10 text-rose-400",
        "acknowledged" => "bg-amber-500/10 text-amber-400",
        "remediated" => "bg-emerald-500/10 text-emerald-400",
        "false_positive" => "bg-slate-500/10 text-slate-400",
        _ => "bg-slate-500/10 text-slate-400",
    }
}

/// Tailwind badge for a scan run status.
pub fn scan_status_badge(status: &str) -> &'static str {
    match status {
        "running" => "bg-sky-500/10 text-sky-400",
        "completed" => "bg-emerald-500/10 text-emerald-400",
        "failed" => "bg-rose-500/10 text-rose-400",
        _ => "bg-slate-500/10 text-slate-400",
    }
}

// ---------------------------------------------------------------------------
// Backend data model (mirrors docs/api.md exactly; `serde(default)` everywhere
// so a missing field never breaks a decode).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanTarget {
    pub id: i64,
    pub name: String,
    pub cidr: String,
    pub ports: Vec<u16>,
    pub enabled: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanRun {
    pub id: i64,
    pub target_id: i64,
    pub target_name: String,
    pub status: String,
    pub hosts_scanned: i64,
    pub hosts_up: i64,
    pub ports_found: i64,
    pub vulns_found: i64,
    pub started_at: i64,
    pub finished_at: i64,
    pub duration_ms: i64,
    pub error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Vulnerability {
    pub id: i64,
    pub scan_id: i64,
    pub target_id: i64,
    pub target_name: String,
    pub host: String,
    pub port: i64,
    pub service: String,
    pub vuln_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub cve: String,
    pub cvss: f64,
    pub status: String,
    pub first_seen_ms: f64,
    pub last_seen_ms: f64,
    pub alert_sent: bool,
    pub created_at: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnStats {
    pub total: i64,
    pub open: i64,
    pub acknowledged: i64,
    pub remediated: i64,
    pub false_positive: i64,
    pub by_severity: SeverityCounts,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ComplianceRule {
    pub id: i64,
    pub name: String,
    pub port: i64,
    pub allowed: bool,
    pub severity: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub target_timeout_ms: i64,
    pub port_timeout_ms: i64,
    pub max_ports_per_host: i64,
    pub compliance_check: bool,
    pub auto_alert: bool,
    pub alert_severity_threshold: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Health {
    pub service: String,
    pub status: String,
    pub db: bool,
    pub vulnerability_stats: VulnStats,
    pub irt_connected: bool,
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Toast {
    pub id: u64,
    pub title: String,
    pub detail: String,
    pub bad: bool,
}

pub const TOAST_KEEP: usize = 5;
pub const TOAST_TTL_MS: u32 = 6_000;

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    /// API key (in-memory only). Empty string = backend is open / no key.
    pub api_key: RwSignal<String>,

    pub health: RwSignal<Health>,
    pub stats: RwSignal<VulnStats>,
    pub surface: RwSignal<AttackSurface>,

    pub targets: SignalVec<ScanTarget>,
    pub scans: SignalVec<ScanRun>,
    pub vulns: SignalVec<Vulnerability>,
    pub rules: SignalVec<ComplianceRule>,

    pub config: RwSignal<ScanConfig>,

    /// Vuln list filters.
    pub filter_status: RwSignal<String>,
    pub filter_severity: RwSignal<String>,

    /// ID of the vulnerability open in the detail drawer (`None` = closed).
    pub open_vuln: RwSignal<Option<i64>>,
    /// Full record of the vulnerability open in the drawer (fetched on select).
    pub open_detail: RwSignal<Option<Vulnerability>>,

    pub conn: RwSignal<ConnStatus>,
    pub toasts: SignalVec<Toast>,
    pub api_error: RwSignal<String>,

    pub metrics: Metrics,
}

/// Aggregate attack-surface summary (`GET /api/v1/attack-surface`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AttackSurface {
    pub targets: i64,
    pub open_vulnerabilities: i64,
    pub by_service: std::collections::BTreeMap<String, i64>,
    pub by_severity: SeverityCounts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnStatus {
    Connecting,
    Open,
    Closed,
}

impl ConnStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "CONNECTING",
            ConnStatus::Open => "LIVE",
            ConnStatus::Closed => "OFFLINE",
        }
    }

    pub fn dot(&self) -> &'static str {
        match self {
            ConnStatus::Connecting => "bg-amber-400 dot-busy",
            ConnStatus::Open => "bg-emerald-400",
            ConnStatus::Closed => "bg-rose-500",
        }
    }
}

#[derive(Clone)]
pub struct Metrics {
    pub next_id: Rc<Cell<u64>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            api_key: signal!(String::new()),
            health: signal!(Health::default()),
            stats: signal!(VulnStats::default()),
            surface: signal!(AttackSurface::default()),
            targets: signal_vec(Vec::new()),
            scans: signal_vec(Vec::new()),
            vulns: signal_vec(Vec::new()),
            rules: signal_vec(Vec::new()),
            config: signal!(ScanConfig::default()),
            filter_status: signal!("all".to_string()),
            filter_severity: signal!("all".to_string()),
            open_vuln: signal!(None),
            open_detail: signal!(None),
            conn: signal!(ConnStatus::Connecting),
            toasts: signal_vec(Vec::new()),
            api_error: signal!(String::new()),
            metrics: Metrics {
                next_id: Rc::new(Cell::new(1)),
            },
        }
    }

    pub fn next_toast_id(&self) -> u64 {
        let id = self.metrics.next_id.get();
        self.metrics.next_id.set(id + 1);
        id
    }
}

/// Bytes → human label (`42.0 MB`). (Kept for parity with other consoles.)
#[allow(dead_code)]
pub fn human_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    let b = b64(b);
    if b >= KB * KB * KB {
        format!("{:.1} GB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{b:.0} B")
    }
}

fn b64(v: u64) -> f64 {
    v as f64
}
