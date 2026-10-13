//! Top bar: brand, IRT link status, and the API-key control.

use veloasm::prelude::*;

use crate::state::AppState;

#[component]
pub fn TopBar() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let health = app.health;
    let service = memo!(move || {
        let h = health.get();
        if h.service.is_empty() {
            "gritscan".to_string()
        } else {
            h.service
        }
    });
    let irt = memo!(move || health.get().irt_connected);
    let conn = app.conn;
    let conn_dot = memo!(move || conn.get().dot().to_string());
    let conn_label = memo!(move || conn.get().label().to_string());

    view! {
        <header class="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
            <div class="container mx-auto px-4 py-3 flex items-center gap-4 max-w-7xl">
                <div class="flex items-center gap-2.5">
                    <div class="h-7 w-7 rounded-md bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center">
                        <span class="text-indigo-400 text-sm font-bold">"GS"</span>
                    </div>
                    <div>
                        <div class="text-base font-bold text-slate-100 leading-none">"GritScan"</div>
                        <div class="text-[10px] uppercase tracking-[2px] text-slate-500 mt-0.5">"Attack Surface Scanner"</div>
                    </div>
                </div>

                <div class="flex-1"></div>

                <div class="flex items-center gap-2 text-[11px] text-slate-500">
                    <span class="font-mono">{ service }</span>
                    <span class="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-slate-800/60 text-slate-400 border border-slate-700/50">
                        <span class={ format!("h-1.5 w-1.5 rounded-full {}", conn_dot.get()) }></span>
                        { conn_label }
                    </span>
                    {
                        move || if irt.get() {
                            view! {
                                <span class="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                    <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
                                    "IRT LINKED"
                                </span>
                            }
                        } else {
                            DomNode::empty()
                        }
                    }
                </div>

                <KeyBar />
            </div>
        </header>
    }
}

/// API-key control. GritScan is open by default; when the backend sets
/// `GS_API_KEY` the operator pastes the key here. It lives in memory only
/// (never localStorage) and rides as `X-API-Key` (and `?api_key=` on the SSE).
#[component]
pub fn KeyBar() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let key_input = signal!(String::new());
    let has_key = memo!(move || !app.api_key.get().trim().is_empty());

    view! {
        <div class="flex items-center gap-2">
            {
                move || if has_key.get() {
                    let app_clear = app.clone();
                    view! {
                        <button
                            class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px] font-semibold"
                            on:click={ move |_| app_clear.api_key.set(String::new()) }>
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
                            "KEY SET — CLEAR"
                        </button>
                    }
                } else {
                    let app_set = app.clone();
                    view! {
                        <div class="flex items-center gap-1.5">
                            <input
                                type="password"
                                class="w-40 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-[11px] font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                                placeholder="X-API-Key (optional)"
                                bind:value={ key_input }
                            />
                            <button
                                class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-[11px] font-semibold"
                                on:click={ move |_| {
                                    let k = key_input.get();
                                    app_set.api_key.set(k.trim().to_string());
                                    crate::net::refresh_all(&app_set);
                                } }>
                                "Apply"
                            </button>
                        </div>
                    }
                }
            }
        </div>
    }
}
