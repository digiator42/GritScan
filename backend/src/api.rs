use gritshield::http::SseStream;
use gritshield::prelude::{RequestContext, Response};
use serde_json::{json, Value};

use crate::db;
use crate::scanner;
use crate::state;

/// `GET /health` — liveness plus a peek at stored counts.
pub async fn health(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    let db_ok = db::ping(st.db.as_ref()).await.is_ok();
    let stats = db::vuln_stats(st.db.as_ref()).await.unwrap_or(json!({}));

    Response::json_ok(&json!({
        "service": "gritscan-backend",
        "status": "ok",
        "db": db_ok,
        "vulnerability_stats": stats,
        "irt_connected": st.irt_url.is_some(),
    }))
}

// ---------------------------------------------------------------------------
// Scan Targets
// ---------------------------------------------------------------------------

/// `POST /api/v1/targets` — add a scan target.
/// Body: `{ "name": "web-servers", "cidr": "10.0.0.0/24", "ports": [80, 443] }`
pub async fn create_target(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({ "error": "invalid_json" })),
    };

    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let cidr = body.get("cidr").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() || cidr.is_empty() {
        return Response::json_bad_request(&json!({ "error": "name_and_cidr_required" }));
    }

    let ports: Vec<u16> = body
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u16))
                .collect()
        })
        .unwrap_or_default();

    match db::insert_target(st.db.as_ref(), name, cidr, &ports).await {
        Ok(id) => Response::json_created(&json!({ "target_id": id, "name": name, "cidr": cidr })),
        Err(e) => Response::json_internal_error_msg(format!("target_create_failed: {e}")),
    }
}

/// `GET /api/v1/targets` — list all scan targets.
pub async fn list_targets(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    match db::list_targets(st.db.as_ref()).await {
        Ok(targets) => Response::json_ok(&json!({ "count": targets.len(), "targets": targets })),
        Err(e) => Response::json_internal_error_msg(format!("list_failed: {e}")),
    }
}

/// `DELETE /api/v1/targets/:id` — remove a scan target.
pub async fn delete_target(ctx: RequestContext) -> Response {
    let st = state::resolve();
    let id = match path_id(&ctx) {
        Some(id) => id,
        None => return Response::json_bad_request(&json!({ "error": "invalid_id" })),
    };

    match db::delete_target(st.db.as_ref(), id).await {
        Ok(()) => Response::json_ok(&json!({ "deleted": true, "target_id": id })),
        Err(e) => Response::json_internal_error_msg(format!("delete_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Scan Runs
// ---------------------------------------------------------------------------

/// `POST /api/v1/scans` — start a scan against a target.
/// Body: `{ "target_id": 1 }`
pub async fn start_scan(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({ "error": "invalid_json" })),
    };

    let target_id = body.get("target_id").and_then(|v| v.as_i64()).unwrap_or(0);
    if target_id <= 0 {
        return Response::json_bad_request(&json!({ "error": "target_id_required" }));
    }

    let target = match db::find_target(st.db.as_ref(), target_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return Response::json_not_found(&json!({ "error": "target_not_found", "target_id": target_id })),
        Err(e) => return Response::json_internal_error_msg(format!("lookup_failed: {e}")),
    };

    if !target.enabled {
        return Response::json_bad_request(&json!({ "error": "target_disabled" }));
    }

    // Check if a scan is already running for this target
    {
        let active = st.active_scans.lock().await;
        if active.contains(&target_id) {
            return Response::json_bad_request(&json!({ "error": "scan_already_running", "target_id": target_id }));
        }
    }

    // Create scan run record
    let run_id = match db::insert_run(st.db.as_ref(), target_id, &target.name).await {
        Ok(id) => id,
        Err(e) => return Response::json_internal_error_msg(format!("run_create_failed: {e}")),
    };

    // Mark scan as active
    {
        let mut active = st.active_scans.lock().await;
        active.insert(target_id);
    }

    // Clone target info before moving into spawn
    let target_name = target.name.clone();

    // Run scan in background
    let st_clone = st.clone();
    tokio::spawn(async move {
        let result = scanner::run_scan(st_clone.clone(), &target, run_id).await;
        let mut active = st_clone.active_scans.lock().await;
        active.remove(&target_id);
        if let Err(e) = result {
            eprintln!("[gritscan] scan {run_id} failed: {e}");
            let _ = db::update_run(
                st_clone.db.as_ref(),
                run_id,
                "failed",
                0,
                0,
                0,
                0,
                &e,
            )
            .await;
        }
    });

    Response::json_accepted(&json!({
        "scan_id": run_id,
        "target_id": target_id,
        "target_name": target_name,
        "status": "running",
    }))
}

/// `GET /api/v1/scans` — list scan runs.
pub async fn list_scans(ctx: RequestContext) -> Response {
    let st = state::resolve();
    let limit = ctx
        .query_param("limit")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50)
        .clamp(1, 500);

    match db::list_runs(st.db.as_ref(), limit).await {
        Ok(runs) => Response::json_ok(&json!({ "count": runs.len(), "scans": runs })),
        Err(e) => Response::json_internal_error_msg(format!("list_failed: {e}")),
    }
}

/// `GET /api/v1/scans/:id` — get a scan run.
pub async fn get_scan(ctx: RequestContext) -> Response {
    let st = state::resolve();
    let id = match path_id(&ctx) {
        Some(id) => id,
        None => return Response::json_bad_request(&json!({ "error": "invalid_id" })),
    };

    match db::find_run(st.db.as_ref(), id).await {
        Ok(Some(run)) => Response::json_ok(&json!({ "scan": run })),
        Ok(None) => Response::json_not_found(&json!({ "error": "scan_not_found", "id": id })),
        Err(e) => Response::json_internal_error_msg(format!("lookup_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

/// `GET /api/v1/vulnerabilities` — list vulnerabilities.
/// Query params: `limit`, `status`, `severity`.
pub async fn list_vulnerabilities(ctx: RequestContext) -> Response {
    let st = state::resolve();
    let limit = ctx
        .query_param("limit")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let status = ctx.query_param("status").map(ToOwned::to_owned);
    let severity = ctx.query_param("severity").map(ToOwned::to_owned);

    match db::list_vulnerabilities(st.db.as_ref(), limit, status.as_deref(), severity.as_deref()).await {
        Ok(vulns) => Response::json_ok(&json!({ "count": vulns.len(), "vulnerabilities": vulns })),
        Err(e) => Response::json_internal_error_msg(format!("list_failed: {e}")),
    }
}

/// `GET /api/v1/vulnerabilities/:id` — get a vulnerability.
pub async fn get_vulnerability(ctx: RequestContext) -> Response {
    let st = state::resolve();
    let id = match path_id(&ctx) {
        Some(id) => id,
        None => return Response::json_bad_request(&json!({ "error": "invalid_id" })),
    };

    match db::find_vulnerability(st.db.as_ref(), id).await {
        Ok(Some(v)) => Response::json_ok(&json!({ "vulnerability": v })),
        Ok(None) => Response::json_not_found(&json!({ "error": "vulnerability_not_found", "id": id })),
        Err(e) => Response::json_internal_error_msg(format!("lookup_failed: {e}")),
    }
}

/// `POST /api/v1/vulnerabilities/:id/status` — update vulnerability status.
/// Body: `{ "status": "acknowledged" | "remediated" | "false_positive" }`
pub async fn update_vuln_status(ctx: RequestContext) -> Response {
    let st = state::resolve();
    let id = match path_id(&ctx) {
        Some(id) => id,
        None => return Response::json_bad_request(&json!({ "error": "invalid_id" })),
    };

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({ "error": "invalid_json" })),
    };

    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status.is_empty() {
        return Response::json_bad_request(&json!({ "error": "status_required" }));
    }

    match db::update_vuln_status(st.db.as_ref(), id, status).await {
        Ok(v) => Response::json_ok(&json!({ "vulnerability": v })),
        Err(e) if e == "vulnerability_not_found" => {
            Response::json_not_found(&json!({ "error": "vulnerability_not_found", "id": id }))
        }
        Err(e) => Response::json_internal_error_msg(format!("update_failed: {e}")),
    }
}

/// `GET /api/v1/vulnerabilities/stats` — vulnerability statistics.
pub async fn vuln_stats(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    match db::vuln_stats(st.db.as_ref()).await {
        Ok(stats) => Response::json_ok(&stats),
        Err(e) => Response::json_internal_error_msg(format!("stats_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Attack Surface
// ---------------------------------------------------------------------------

/// `GET /api/v1/attack-surface` — attack surface summary.
pub async fn attack_surface(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    match scanner::attack_surface_summary(st.clone()).await {
        Ok(summary) => Response::json_ok(&summary),
        Err(e) => Response::json_internal_error_msg(format!("summary_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

/// `GET /api/v1/compliance/rules` — list compliance rules.
pub async fn list_compliance_rules(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    match db::list_compliance_rules(st.db.as_ref()).await {
        Ok(rules) => Response::json_ok(&json!({ "count": rules.len(), "rules": rules })),
        Err(e) => Response::json_internal_error_msg(format!("list_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// `GET /api/v1/config` — get scan configuration.
pub async fn get_config(_ctx: RequestContext) -> Response {
    let st = state::resolve();
    match db::get_config(st.db.as_ref()).await {
        Ok(config) => Response::json_ok(&config),
        Err(e) => Response::json_internal_error_msg(format!("config_failed: {e}")),
    }
}

/// `POST /api/v1/config` — update scan configuration.
pub async fn update_config(ctx: RequestContext) -> Response {
    let st = state::resolve();

    let body: Value = match ctx.json_body().await {
        Some(v) => v,
        None => return Response::json_bad_request(&json!({ "error": "invalid_json" })),
    };

    let mut config = match db::get_config(st.db.as_ref()).await {
        Ok(c) => c,
        Err(e) => return Response::json_internal_error_msg(format!("config_failed: {e}")),
    };

    if let Some(v) = body.get("target_timeout_ms").and_then(|v| v.as_u64()) {
        config.target_timeout_ms = v;
    }
    if let Some(v) = body.get("port_timeout_ms").and_then(|v| v.as_u64()) {
        config.port_timeout_ms = v;
    }
    if let Some(v) = body.get("max_ports_per_host").and_then(|v| v.as_u64()) {
        config.max_ports_per_host = v as u32;
    }
    if let Some(v) = body.get("compliance_check").and_then(|v| v.as_bool()) {
        config.compliance_check = v;
    }
    if let Some(v) = body.get("auto_alert").and_then(|v| v.as_bool()) {
        config.auto_alert = v;
    }
    if let Some(v) = body.get("alert_severity_threshold").and_then(|v| v.as_str()) {
        config.alert_severity_threshold = v.to_string();
    }

    match db::update_config(st.db.as_ref(), &config).await {
        Ok(()) => {
            // Note: config is behind Arc, so we update the DB only.
            // The in-memory copy is read at boot. For runtime changes,
            // we'd need a RwLock. For now, DB is source of truth.
            Response::json_ok(&config)
        }
        Err(e) => Response::json_internal_error_msg(format!("config_update_failed: {e}")),
    }
}

// ---------------------------------------------------------------------------
// SSE Stream
// ---------------------------------------------------------------------------

/// `GET /api/v1/stream` — SSE feed of scan events.
pub async fn stream(_ctx: RequestContext) -> Response {
    let _st = state::resolve();
    let sse = SseStream::new();
    // For now, just return an empty stream. In a full implementation,
    // this would publish scan events as they happen.
    Response::sse(sse)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn path_id(ctx: &RequestContext) -> Option<i64> {
    ctx.param("id").and_then(|s| s.parse().ok())
}
