//! GritScan console — proactive attack surface scanner as a Veloasm SPA.
//!
//! - Register / delete scan targets (CIDR + port list)
//! - Kick scans and watch history
//! - Filterable vulnerability list with a detail drawer + status workflow
//! - Attack-surface breakdown (service + severity)
//! - Compliance rules and scan configuration
//! - Live SSE feed (`GET /api/v1/stream`) for scan events
//!
//! Auth is an optional API key held in memory only, sent as `X-API-Key`
//! (and `?api_key=` on the SSE, which cannot set headers).

use veloasm::prelude::*;
use wasm_bindgen::prelude::wasm_bindgen;

mod api;
mod components;
mod net;
mod state;

use crate::components::*;
use crate::state::AppState;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    run_app();
}

pub fn run_app() {
    // Seed global context before mounting so every component can pull the
    // shared state with `use_context::<AppState>()`.
    let app = AppState::new();
    provide!(app.clone());

    // Initial load + 10 s poll + SSE stream.
    net::start_poll(&app);
    net::connect(&app);

    let shell = view! {
        <div class="min-h-screen bg-slate-950 text-slate-200 text-sm">
            <TopBar />
            <main class="container mx-auto px-4 py-6 space-y-6 max-w-7xl">
                <MetricsTiles />
                <AttackSurface />
                <TargetsPanel />
                <ScansTable />
                <VulnsTable />
                <div class="grid gap-6 lg:grid-cols-2">
                    <Compliance />
                    <ConfigPanel />
                </div>
                <div class="font-mono text-xs text-rose-400">{ app.api_error.clone() }</div>
            </main>
            <VulnDrawer />
            <ToastStack />
        </div>
    };
    mount(shell);
}
