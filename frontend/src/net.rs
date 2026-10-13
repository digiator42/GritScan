//! Live data wiring for the GritScan console.
//!
//! - SSE feed (`GET /api/v1/stream`) for scan events. The backend currently
//!   returns an empty stream, but the client is future-proof: it parses the
//!   documented `scan_started` / `scan_completed` / `vulnerability_found`
//!   event data and refreshes the affected views. `EventSource` auto-reconnects
//!   and cannot send headers, so the API key travels via `?api_key=` (see
//!   [`crate::api::stream_url`]).
//! - Polling for the slower REST reads (health, stats, scans) on a 10 s tick.

use std::cell::RefCell;

use serde::Deserialize;
use veloasm::prelude::*;
use veloasm::sse;

use crate::api;
use crate::state::{AppState, ConnStatus};

thread_local! {
    /// The live SSE connection, if any. `SseConnection` is not `Clone`.
    static STREAM: RefCell<Option<sse::SseConnection>> = const { RefCell::new(None) };
    /// `true` while the app wants the stream up.
    static WANTED: RefCell<bool> = const { RefCell::new(false) };
}

/// One event frame from the stream. The backend names events but the data
/// payload is JSON; unknown events are ignored. We only care that *something*
/// arrived (to mark the feed live + refresh), so no fields are decoded.
#[derive(Debug, Deserialize, Default)]
struct StreamEvent {
    #[serde(default)]
    #[allow(dead_code)]
    scan_id: i64,
}

/// Open the SSE stream (no-op when already open). Refresh logic lives in the
/// message handler below.
pub fn connect(app: &AppState) {
    WANTED.with(|w| *w.borrow_mut() = true);
    if STREAM.with(|s| s.borrow().is_some()) {
        return;
    }
    open_stream(app);
}

fn open_stream(app: &AppState) {
    app.conn.set(ConnStatus::Connecting);
    let url = api::stream_url(app);

    let app_for_open = app.clone();
    match sse::connect(&url, move |raw| {
        handle_frame(&app_for_open, &raw);
    }) {
        Ok(conn) => {
            let app_open = app.clone();
            let _ = sse::on_open(&conn, move || {
                app_open.conn.set(ConnStatus::Open);
            });
            STREAM.with(|slot| *slot.borrow_mut() = Some(conn));
        }
        Err(_) => {
            // EventSource constructor failure — mark offline; it will be
            // retried on the next connect() call / reload.
            app.conn.set(ConnStatus::Closed);
        }
    }
}

fn handle_frame(app: &AppState, raw: &str) {
    // Parse best-effort; the stream may emit keep-alive/comment frames whose
    // data is not JSON, which we ignore.
    let Ok(_ev) = serde_json::from_str::<StreamEvent>(raw) else {
        return;
    };
    // Any event means the feed is live and the backend state may have moved.
    app.conn.set(ConnStatus::Open);
    refresh_all(app);
}

fn close_stream_only() {
    STREAM.with(|slot| {
        if let Some(conn) = slot.borrow_mut().take() {
            conn.close();
        }
    });
}

/// Stop the stream (used on logout / teardown).
#[allow(dead_code)]
pub fn disconnect() {
    WANTED.with(|w| *w.borrow_mut() = false);
    close_stream_only();
    // EventSource reconnects on its own; to fully stop, the page must go away.
}

// ---------------------------------------------------------------------------
// Polling refresh
// ---------------------------------------------------------------------------

/// Refresh every REST-backed view. Cheap enough to call on stream events and
/// on the initial load; heavy enough to warrant the 10 s poll rather than a
/// per-event storm.
pub fn refresh_all(app: &AppState) {
    let app = app.clone();
    wasm_bindgen_futures::spawn_local(async move {
        refresh_health(&app).await;
        refresh_stats(&app).await;
        refresh_surface(&app).await;
        refresh_targets(&app).await;
        refresh_scans(&app).await;
        refresh_vulns(&app).await;
        refresh_rules(&app).await;
        refresh_config(&app).await;
    });
}

async fn refresh_health(app: &AppState) {
    if let Ok(h) = api::health(app).await {
        app.api_error.set(String::new());
        app.health.set(crate::state::Health {
            service: h.service,
            status: h.status,
            db: h.db,
            vulnerability_stats: h.vulnerability_stats,
            irt_connected: h.irt_connected,
        });
    }
}

async fn refresh_stats(app: &AppState) {
    if let Ok(s) = api::vuln_stats(app).await {
        app.stats.set(s);
    }
}

async fn refresh_surface(app: &AppState) {
    if let Ok(a) = api::attack_surface(app).await {
        app.surface.set(crate::state::AttackSurface {
            targets: a.targets,
            open_vulnerabilities: a.open_vulnerabilities,
            by_service: a.by_service,
            by_severity: a.by_severity,
        });
    }
}

async fn refresh_scans(app: &AppState) {
    if let Ok(r) = api::list_scans(app, 20).await {
        app.scans.with_mut(|v| *v = r.scans);
    }
}

async fn refresh_targets(app: &AppState) {
    if let Ok(r) = api::list_targets(app).await {
        app.targets.with_mut(|v| *v = r.targets);
    }
}

async fn refresh_rules(app: &AppState) {
    if let Ok(r) = api::compliance_rules(app).await {
        app.rules.with_mut(|v| *v = r.rules);
    }
}

async fn refresh_config(app: &AppState) {
    if let Ok(c) = api::get_config(app).await {
        app.config.set(c);
    }
}

async fn refresh_vulns(app: &AppState) {
    let status = app.filter_status.get();
    let severity = app.filter_severity.get();
    if let Ok(r) = api::list_vulns(app, &status, &severity, 200).await {
        app.vulns.with_mut(|v| *v = r.vulnerabilities);
    }
}

/// Refresh only the vulnerability list (used after filter changes).
pub fn refresh_vulns_only(app: &AppState) {
    let app = app.clone();
    wasm_bindgen_futures::spawn_local(async move {
        refresh_vulns(&app).await;
    });
}

/// Start the 10 s background poll. Called once after the first load.
pub fn start_poll(app: &AppState) {
    refresh_all(app);
    let app = app.clone();
    let _interval = gloo_timers::callback::Interval::new(10_000, move || {
        refresh_all(&app);
    });
    std::mem::forget(_interval);
}
