//! Vulnerability detail drawer: slides in from the right when a row is
//! selected. Shows full metadata + remediation and lets the operator update
//! the status (open / acknowledged / remediated / false_positive).

use veloasm::prelude::*;

use crate::components::push_toast;
use crate::state::{AppState, STATUSES, severity_badge, status_badge};

#[component]
pub fn VulnDrawer() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");

    // Fetch the full record whenever the selection changes.
    let sel = app.open_vuln;
    let app_fetch = app.clone();
    create_effect(move || {
        if let Some(id) = sel.get() {
            let app = app_fetch.clone();
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(r) = crate::api::get_vuln(&app, id).await {
                    app.open_detail.set(Some(r.vulnerability));
                }
            });
        } else {
            app_fetch.open_detail.set(None);
        }
    });

    let open = memo!(move || app.open_vuln.get().is_some());
    let detail = app.open_detail;

    view! {
        <div
            class="fixed inset-y-0 right-0 z-40 w-full max-w-md bg-slate-950 border-l border-slate-800 shadow-2xl flex flex-col transition-transform duration-200"
            style:transform={ move || if open.get() { "translateX(0%)".to_string() } else { "translateX(100%)".to_string() } }
        >
            {
                move || {
                    if let Some(v) = detail.get() {
                        let app = app.clone();
                        let sev_badge = severity_badge(&v.severity).to_string();
                        let endpoint = format!("{}:{}", v.host, v.port);
                        let cvss = if v.cvss > 0.0 {
                            format!("{:.1}", v.cvss)
                        } else {
                            "—".to_string()
                        };
                        let alert = if v.alert_sent { "yes".to_string() } else { "no".to_string() };
                        view! {
                            <div class="flex flex-col h-full">
                                // header
                                <div class="px-5 py-4 border-b border-slate-800 flex items-start gap-3">
                                    <div class="flex-1 min-w-0">
                                        <div class={ format!("inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase mb-2 {}", sev_badge) }>
                                            { v.severity.clone() }
                                        </div>
                                        <h2 class="text-sm font-bold text-slate-100 leading-snug">{ v.title.clone() }</h2>
                                        <div class="text-[11px] font-mono text-slate-500 mt-1">{ endpoint }</div>
                                    </div>
                                    <button
                                        class="text-slate-500 hover:text-slate-300 text-lg leading-none px-1"
                                        on:click={ move |_| {
                                            app.open_vuln.set(None);
                                            app.open_detail.set(None);
                                        } }>
                                        "×"
                                    </button>
                                </div>

                                // body
                                <div class="flex-1 overflow-y-auto scrollthin px-5 py-4 space-y-4 text-xs">
                                    <div class="grid grid-cols-2 gap-3">
                                        <Field label="Service" value={ v.service.clone() } />
                                        <Field label="Type" value={ v.vuln_type.clone() } />
                                        <Field label="Target" value={ v.target_name.clone() } />
                                        <Field label="CVSS" value={ cvss } />
                                        <Field label="CVE / CWE" value={ v.cve.clone() } />
                                        <Field label="Alert sent" value={ alert } />
                                    </div>

                                    <div>
                                        <div class="text-[10px] uppercase tracking-wide text-slate-500 mb-1">"Description"</div>
                                        <p class="text-slate-300 leading-relaxed">{ v.description.clone() }</p>
                                    </div>

                                    <div>
                                        <div class="text-[10px] uppercase tracking-wide text-slate-500 mb-1">"Remediation"</div>
                                        <p class="text-emerald-300/90 leading-relaxed">{ v.remediation.clone() }</p>
                                    </div>
                                </div>

                                // status update footer
                                <div class="px-5 py-4 border-t border-slate-800 space-y-2">
                                    <div class="text-[10px] uppercase tracking-wide text-slate-500">"Update status"</div>
                                    <div class="flex flex-wrap gap-2">
                                        {
                                            for s in STATUSES.iter().copied() {
                                                <StatusButton id={ v.id } status={ s.to_string() } />
                                            }
                                        }
                                    </div>
                                </div>
                            </div>
                        }
                    } else {
                        DomNode::empty()
                    }
                }
            }
        </div>
    }
}

#[component]
fn Field(label: &'static str, value: String) -> DomNode {
    view! {
        <div>
            <div class="text-[10px] uppercase tracking-wide text-slate-500">{ label }</div>
            <div class="text-slate-200 font-mono mt-0.5 break-words">{ value }</div>
        </div>
    }
}

#[component]
fn StatusButton(id: i64, status: String) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let badge = status_badge(&status).to_string();
    let st = status.clone();
    view! {
        <button
            class={ format!("px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:border-indigo-500 text-xs font-semibold {}", badge) }
            on:click={ move |_| {
                let app = app.clone();
                let st = st.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    match crate::api::update_vuln_status(&app, id, &st).await {
                        Ok(r) => {
                            push_toast(
                                &app,
                                "Status updated".into(),
                                format!("#{} → {}", r.vulnerability.id, st),
                                false,
                            );
                            app.open_vuln.set(None);
                            app.open_detail.set(None);
                            crate::net::refresh_all(&app);
                        }
                        Err(e) => push_toast(&app, "Update failed".into(), e.to_string(), true),
                    }
                });
            } }>
            { status }
        </button>
    }
}
