use gritshield::mcp_prompt;
use gritshield::mcp_tool;
use gritshield::routing::engine::RequestContext;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db;
use crate::scanner;
use crate::state;


// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AddTargetArgs {
    pub name: String,
    pub cidr: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

/// `tools/call add_target` — register a new scan target.
#[mcp_tool(
    name = "add_target",
    service = "GritScan",
    description = "Register a new scan target (host or subnet) for periodic attack surface scanning",
    schema = r#"{
        "type": "object",
        "properties": {
            "name": { "type": "string", "description": "Human-readable target name" },
            "cidr":  { "type": "string", "description": "CIDR notation, e.g. 10.0.0.0/24" },
            "ports": { "type": "array", "items": { "type": "integer" }, "description": "Ports to scan (empty = well-known)" }
        },
        "required": ["name", "cidr"]
    }"#,
)]
pub async fn add_target(_ctx: &RequestContext, args: AddTargetArgs) -> Result<Value, String> {
    let st = state::resolve();
    let id = db::insert_target(st.db.as_ref(), &args.name, &args.cidr, &args.ports).await?;
    Ok(json!({ "target_id": id, "name": args.name, "cidr": args.cidr }))
}

#[derive(Debug, Deserialize)]
pub struct ScanTargetArgs {
    pub target_id: i64,
}

/// `tools/call run_scan` — trigger a scan against a target.
#[mcp_tool(
    name = "run_scan",
    service = "GritScan",
    description = "Trigger an immediate scan against a registered target. Returns a scan id; results are available via list_vulnerabilities.",
    schema = r#"{
        "type": "object",
        "properties": {
            "target_id": { "type": "integer", "description": "Target id to scan" }
        },
        "required": ["target_id"]
    }"#,
)]
pub async fn run_scan_tool(_ctx: &RequestContext, args: ScanTargetArgs) -> Result<Value, String> {
    let st = state::resolve();

    let target = db::find_target(st.db.as_ref(), args.target_id)
        .await?
        .ok_or_else(|| format!("target {} not found", args.target_id))?;

    let run_id = db::insert_run(st.db.as_ref(), target.id, &target.name).await?;

    {
        let mut active = st.active_scans.lock().await;
        active.insert(target.id);
    }

    let target_id = target.id;
    let st_clone = st.clone();
    tokio::spawn(async move {
        let result = scanner::run_scan(st_clone.clone(), &target, run_id).await;
        let mut active = st_clone.active_scans.lock().await;
        active.remove(&target_id);
        if let Err(e) = result {
            let _ = db::update_run(st_clone.db.as_ref(), run_id, "failed", 0, 0, 0, 0, &e).await;
        }
    });

    Ok(json!({ "scan_id": run_id, "target_id": target_id, "status": "running" }))
}

#[derive(Debug, Deserialize)]
pub struct ListVulnsArgs {
    #[serde(default)]
    pub limit: u32,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

/// `tools/call list_vulnerabilities` — list detected vulnerabilities.
#[mcp_tool(
    name = "list_vulnerabilities",
    service = "GritScan",
    description = "List detected vulnerabilities, optionally filtered by status and severity",
    schema = r#"{
        "type": "object",
        "properties": {
            "limit":   { "type": "integer", "description": "Max results (default 100)", "minimum": 1, "maximum": 1000 },
            "status":  { "type": "string", "enum": ["open", "acknowledged", "remediated", "false_positive"] },
            "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] }
        },
        "required": []
    }"#,
)]
pub async fn list_vulnerabilities_tool(
    _ctx: &RequestContext,
    args: ListVulnsArgs,
) -> Result<Value, String> {
    let st = state::resolve();
    let limit = if args.limit == 0 { 100 } else { args.limit.clamp(1, 1000) } as u64;
    let vulns = db::list_vulnerabilities(
        st.db.as_ref(),
        limit,
        args.status.as_deref(),
        args.severity.as_deref(),
    )
    .await?;
    Ok(json!({ "count": vulns.len(), "vulnerabilities": vulns }))
}

#[derive(Debug, Deserialize)]
pub struct VulnIdArgs {
    pub vulnerability_id: i64,
}

/// `tools/call get_vulnerability` — get full details of a vulnerability.
#[mcp_tool(
    name = "get_vulnerability",
    service = "GritScan",
    description = "Get full details of a specific vulnerability finding",
    schema = r#"{
        "type": "object",
        "properties": {
            "vulnerability_id": { "type": "integer" }
        },
        "required": ["vulnerability_id"]
    }"#,
)]
pub async fn get_vulnerability_tool(_ctx: &RequestContext, args: VulnIdArgs) -> Result<Value, String> {
    let st = state::resolve();
    let vuln = db::find_vulnerability(st.db.as_ref(), args.vulnerability_id)
        .await?
        .ok_or_else(|| format!("vulnerability {} not found", args.vulnerability_id))?;
    Ok(json!({ "vulnerability": vuln }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusArgs {
    pub vulnerability_id: i64,
    pub status: String,
}

/// `tools/call update_vulnerability_status` — update vulnerability status.
#[mcp_tool(
    name = "update_vulnerability_status",
    service = "GritScan",
    description = "Update the status of a vulnerability (acknowledge, remediate, or mark false positive)",
    schema = r#"{
        "type": "object",
        "properties": {
            "vulnerability_id": { "type": "integer" },
            "status":          { "type": "string", "enum": ["open", "acknowledged", "remediated", "false_positive"] }
        },
        "required": ["vulnerability_id", "status"]
    }"#,
)]
pub async fn update_status_tool(_ctx: &RequestContext, args: UpdateStatusArgs) -> Result<Value, String> {
    let st = state::resolve();
    let vuln = db::update_vuln_status(st.db.as_ref(), args.vulnerability_id, &args.status).await?;
    Ok(json!({ "vulnerability": vuln }))
}

/// `tools/call get_attack_surface` — attack surface summary.
#[mcp_tool(
    name = "get_attack_surface",
    service = "GritScan",
    description = "Get a summary of the current attack surface: open vulnerabilities, exposed services, and risk breakdown",
    schema = r#"{ "type": "object", "properties": {}, "required": [] }"#,
)]
pub async fn get_attack_surface_tool(_ctx: &RequestContext, _args: Value) -> Result<Value, String> {
    let st = state::resolve();
    scanner::attack_surface_summary(st.clone()).await
}

/// `tools/call list_scan_targets` — list all registered scan targets.
#[mcp_tool(
    name = "list_scan_targets",
    service = "GritScan",
    description = "List all registered scan targets",
    schema = r#"{ "type": "object", "properties": {}, "required": [] }"#,
)]
pub async fn list_scan_targets_tool(_ctx: &RequestContext, _args: Value) -> Result<Value, String> {
    let st = state::resolve();
    let targets = db::list_targets(st.db.as_ref()).await?;
    Ok(json!({ "count": targets.len(), "targets": targets }))
}

/// `tools/call get_vulnerability_stats` — vulnerability statistics.
#[mcp_tool(
    name = "get_vulnerability_stats",
    service = "GritScan",
    description = "Get vulnerability statistics: counts by status and severity",
    schema = r#"{ "type": "object", "properties": {}, "required": [] }"#,
)]
pub async fn get_vulnerability_stats_tool(
    _ctx: &RequestContext,
    _args: Value,
) -> Result<Value, String> {
    let st = state::resolve();
    db::vuln_stats(st.db.as_ref()).await
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RemediationArgs {
    pub vulnerability_id: i64,
}

/// `prompts/get remediation_plan` — build a remediation plan for a vulnerability.
#[mcp_prompt(
    name = "remediation_plan",
    description = "Build a step-by-step remediation plan for a vulnerability finding",
    arguments = "vulnerability_id",
    descriptions = "vulnerability_id=Vulnerability id to build a plan for"
)]
pub async fn remediation_plan(args: RemediationArgs) -> Result<Vec<gritshield::mcp::prompt::McpPromptMessage>, String> {
    let st = state::resolve();
    let vuln = db::find_vulnerability(st.db.as_ref(), args.vulnerability_id)
        .await?
        .ok_or_else(|| format!("vulnerability {} not found", args.vulnerability_id))?;

    let message = format!(
        "You are a security engineer. Build a concise remediation plan for this vulnerability.\n\n\
         Title: {}\n\
         Host: {}:{}\n\
         Service: {}\n\
         Severity: {}\n\
         Type: {}\n\
         Description: {}\n\
         Remediation: {}\n\
         CVE: {}\n\
         CVSS: {}\n\n\
         Provide: (1) immediate containment steps, (2) permanent fix, (3) verification steps, \
         (4) estimated effort, and (5) any rollback considerations.",
        vuln.title,
        vuln.host,
        vuln.port,
        vuln.service,
        vuln.severity,
        vuln.vuln_type,
        vuln.description,
        vuln.remediation,
        vuln.cve.as_deref().unwrap_or("N/A"),
        vuln.cvss.map(|v| v.to_string()).unwrap_or_else(|| "N/A".to_string()),
    );

    Ok(vec![gritshield::mcp::prompt::McpPromptMessage::user(message)])
}
