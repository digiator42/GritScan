//! Targets panel: register / delete scan targets (CIDR + port list).

use veloasm::prelude::*;

use crate::components::push_toast;
use crate::state::{AppState, ScanTarget};

#[component]
pub fn TargetsPanel() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let name_input = signal!(String::new());
    let cidr_input = signal!(String::new());
    let ports_input = signal!(String::new());

    let targets = app.targets.clone();

    view! {
        <section class="rounded-xl border border-slate-800 bg-slate-900/40">
            <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-sm font-bold text-slate-200 uppercase tracking-wide">"Scan Targets"</h2>
            </div>

            // --- add-target form -------------------------------------------
            <div class="p-4 border-b border-slate-800 flex flex-wrap gap-2 items-end">
                <div class="flex flex-col gap-1">
                    <label class="text-[10px] uppercase tracking-wide text-slate-500">"Name"</label>
                    <input type="text"
                        class="w-40 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        placeholder="web-servers"
                        bind:value={ name_input } />
                </div>
                <div class="flex flex-col gap-1">
                    <label class="text-[10px] uppercase tracking-wide text-slate-500">"CIDR"</label>
                    <input type="text"
                        class="w-44 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                        placeholder="10.0.0.0/24"
                        bind:value={ cidr_input } />
                </div>
                <div class="flex flex-col gap-1">
                    <label class="text-[10px] uppercase tracking-wide text-slate-500">"Ports (comma, blank = well-known)"</label>
                    <input type="text"
                        class="w-56 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                        placeholder="80,443,8080"
                        bind:value={ ports_input } />
                </div>
                <button
                    class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold"
                    on:click={ move |_| {
                        let app = app.clone();
                        let name = name_input.get();
                        let cidr = cidr_input.get();
                        let ports_raw = ports_input.get();
                        if name.trim().is_empty() || cidr.trim().is_empty() {
                            push_toast(&app, "Missing fields".into(), "name and CIDR are required".into(), true);
                            return;
                        }
                        let ports: Vec<u16> = ports_raw
                            .split(',')
                            .filter_map(|p| p.trim().parse::<u16>().ok())
                            .collect();
                        wasm_bindgen_futures::spawn_local(async move {
                            match crate::api::add_target(&app, name.trim(), cidr.trim(), ports).await {
                                Ok(r) => {
                                    push_toast(&app, "Target added".into(), format!("{} ({})", r.name, r.cidr), false);
                                    crate::net::refresh_all(&app);
                                }
                                Err(e) => push_toast(&app, "Add failed".into(), e.to_string(), true),
                            }
                        });
                    } }>
                    "Add Target"
                </button>
            </div>

            // --- list ------------------------------------------------------
            <div class="divide-y divide-slate-800/60">
                {
                    for t in targets key = |t: &ScanTarget| t.id {
                        <TargetRow target={ t.clone() } />
                    }
                }
            </div>
        </section>
    }
}

#[component]
fn TargetRow(target: ScanTarget) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let ports_label = if target.ports.is_empty() {
        "well-known".to_string()
    } else {
        target.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
    };
    let id = target.id;
    let cidr = target.cidr.clone();
    let name = target.name.clone();

    // One state clone per button; signals are `Copy` and move freely.
    let app_scan = app.clone();
    let app_del = app.clone();

    view! {
        <div class="px-4 py-2.5 flex items-center gap-3 text-xs">
            <span class="font-semibold text-slate-200">{ name }</span>
            <span class="font-mono text-slate-400">{ cidr }</span>
            <span class="text-slate-600">"."</span>
            <span class="font-mono text-slate-500">{ ports_label }</span>
            <div class="flex-1"></div>
            <button
                class="px-2 py-1 rounded-md bg-indigo-600/20 hover:bg-indigo-600 border border-indigo-500/30 text-indigo-300 font-semibold"
                on:click={ move |_| {
                    let app = app_scan.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        match crate::api::start_scan(&app, id).await {
                            Ok(r) => push_toast(&app, "Scan started".into(), format!("{} (#{})", r.target_name, r.scan_id), false),
                            Err(e) => push_toast(&app, "Scan failed".into(), e.to_string(), true),
                        }
                        crate::net::refresh_all(&app);
                    });
                } }>
                "Run Scan"
            </button>
            <button
                class="px-2 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 font-semibold"
                on:click={ move |_| {
                    let app = app_del.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        match crate::api::delete_target(&app, id).await {
                            Ok(_) => {
                                push_toast(&app, "Target removed".into(), format!("#{id}"), false);
                                crate::net::refresh_all(&app);
                            }
                            Err(e) => push_toast(&app, "Delete failed".into(), e.to_string(), true),
                        }
                    });
                } }>
                "Delete"
            </button>
        </div>
    }
}
