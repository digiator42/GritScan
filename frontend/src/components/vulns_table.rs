//! Vulnerabilities table: filterable list (status + severity), each row opens
//! the detail drawer. This is the heart of the console.

use veloasm::prelude::*;

use crate::state::{AppState, Vulnerability, severity_bar, severity_text, status_badge};

#[component]
pub fn VulnsTable() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let vulns = app.vulns.clone();
    let filter_status = app.filter_status;
    let filter_severity = app.filter_severity;

    // Refresh the list whenever either filter changes.
    let app_refresh = app.clone();
    let fs = filter_status;
    create_effect(move || {
        let _ = fs.get();
        crate::net::refresh_vulns_only(&app_refresh);
    });
    let app_refresh2 = app.clone();
    let fv = filter_severity;
    create_effect(move || {
        let _ = fv.get();
        crate::net::refresh_vulns_only(&app_refresh2);
    });

    view! {
        <section class="rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col">
            <div class="px-4 py-3 border-b border-slate-800 flex items-center gap-3 flex-wrap">
                <h2 class="text-sm font-bold text-slate-200 uppercase tracking-wide">"Vulnerabilities"</h2>
                <div class="flex-1"></div>
                <label class="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-slate-500">
                    "STATUS"
                    <select
                        class="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        bind:value={ filter_status }>
                        <option value="all">"all"</option>
                        <option value="open">"open"</option>
                        <option value="acknowledged">"acknowledged"</option>
                        <option value="remediated">"remediated"</option>
                        <option value="false_positive">"false_positive"</option>
                    </select>
                </label>
                <label class="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-slate-500">
                    "SEVERITY"
                    <select
                        class="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        bind:value={ filter_severity }>
                        <option value="all">"all"</option>
                        <option value="critical">"critical"</option>
                        <option value="high">"high"</option>
                        <option value="medium">"medium"</option>
                        <option value="low">"low"</option>
                    </select>
                </label>
            </div>
            <div class="divide-y divide-slate-800/50 overflow-y-auto scrollthin max-h-[620px]">
                {
                    for v in vulns key = |v: &Vulnerability| v.id {
                        <VulnRow vuln={ v.clone() } />
                    }
                }
            </div>
        </section>
    }
}

#[component]
fn VulnRow(vuln: Vulnerability) -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let id = vuln.id;
    let endpoint = format!("{}:{}", vuln.host, vuln.port);
    let bar = severity_bar(&vuln.severity).to_string();
    let sev_text = severity_text(&vuln.severity).to_string();
    let badge = status_badge(&vuln.status).to_string();
    let cvss = if vuln.cvss > 0.0 {
        format!("{:.1}", vuln.cvss)
    } else {
        "—".to_string()
    };

    view! {
        <button
            class="w-full text-left px-4 py-2.5 flex items-center gap-3 hover:bg-slate-800/40 transition-colors"
            on:click={ move |_| app.open_vuln.set(Some(id)) }>
            <span class={ format!("h-8 w-1 rounded-full {}", bar) }></span>
            <span class="flex-1 min-w-0">
                <span class="block text-xs font-semibold text-slate-200 truncate">{ vuln.title.clone() }</span>
                <span class="block text-[11px] font-mono text-slate-500 truncate">{ endpoint }</span>
            </span>
            <span class={ format!("px-2 py-0.5 rounded text-[10px] font-bold uppercase {}", sev_text) }>{ vuln.severity.clone() }</span>
            <span class="text-[11px] font-mono text-slate-400 w-10 text-right">{ cvss }</span>
            <span class={ format!("px-2 py-0.5 rounded text-[10px] font-semibold {}", badge) }>{ vuln.status.clone() }</span>
        </button>
    }
}
