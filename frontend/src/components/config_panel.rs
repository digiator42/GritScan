//! Scan configuration panel: view + edit the scanner's runtime settings
//! (timeouts, auto-alert, alert severity threshold).

use veloasm::prelude::*;

use crate::components::push_toast;
use crate::state::AppState;

#[component]
pub fn ConfigPanel() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    let target_timeout = signal!(String::new());
    let port_timeout = signal!(String::new());
    let max_ports = signal!(String::new());
    let auto_alert = signal!(false);
    let threshold = signal!(String::new());

    // Seed the inputs from the loaded config (runs once; config rarely changes).
    let app_seed = app.clone();
    create_effect(move || {
        let c = app_seed.config.get();
        if c.target_timeout_ms != 0 || !c.alert_severity_threshold.is_empty() {
            target_timeout.set(c.target_timeout_ms.to_string());
            port_timeout.set(c.port_timeout_ms.to_string());
            max_ports.set(c.max_ports_per_host.to_string());
            auto_alert.set(c.auto_alert);
            threshold.set(c.alert_severity_threshold.clone());
        }
    });

    let app_save = app.clone();
    let threshold_sel = threshold;

    view! {
        <section class="rounded-xl border border-slate-800 bg-slate-900/40">
            <div class="px-4 py-3 border-b border-slate-800">
                <h2 class="text-sm font-bold text-slate-200 uppercase tracking-wide">"Scan Configuration"</h2>
            </div>
            <div class="p-4 grid gap-4 md:grid-cols-2">
                <NumField label="Target timeout (ms)" signal={ target_timeout } />
                <NumField label="Port timeout (ms)" signal={ port_timeout } />
                <NumField label="Max ports / host" signal={ max_ports } />

                <div class="flex items-center gap-2">
                    <input type="checkbox" bind:checked={ auto_alert } class="h-4 w-4 accent-indigo-500" />
                    <label class="text-xs text-slate-300">"Auto-alert critical findings to GritIRT"</label>
                </div>

                <label class="flex flex-col gap-1">
                    <span class="text-[10px] uppercase tracking-wide text-slate-500">"Alert threshold"</span>
                    <select class="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        bind:value={ threshold_sel }>
                        <option value="low">"low"</option>
                        <option value="medium">"medium"</option>
                        <option value="high">"high"</option>
                        <option value="critical">"critical"</option>
                    </select>
                </label>

                <div class="md:col-span-2">
                    <button
                        class="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold"
                        on:click={ move |_| {
                            let app = app_save.clone();
                            let cfg = crate::state::ScanConfig {
                                target_timeout_ms: target_timeout.get().trim().parse().unwrap_or(5000),
                                port_timeout_ms: port_timeout.get().trim().parse().unwrap_or(2000),
                                max_ports_per_host: max_ports.get().trim().parse().unwrap_or(1000),
                                compliance_check: true,
                                auto_alert: auto_alert.get(),
                                alert_severity_threshold: threshold_sel.get(),
                            };
                            wasm_bindgen_futures::spawn_local(async move {
                                match crate::api::update_config(&app, &cfg).await {
                                    Ok(updated) => {
                                        push_toast(
                                            &app,
                                            "Config saved".into(),
                                            format!("auto_alert={}", updated.auto_alert),
                                            false,
                                        );
                                        app.config.set(updated);
                                    }
                                    Err(e) => push_toast(&app, "Save failed".into(), e.to_string(), true),
                                }
                            });
                        } }>
                        "Save Configuration"
                    </button>
                </div>
            </div>
        </section>
    }
}

#[component]
fn NumField(label: &'static str, signal: RwSignal<String>) -> DomNode {
    view! {
        <label class="flex flex-col gap-1">
            <span class="text-[10px] uppercase tracking-wide text-slate-500">{ label }</span>
            <input type="text" inputmode="numeric"
                class="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                bind:value={ signal } />
        </label>
    }
}
