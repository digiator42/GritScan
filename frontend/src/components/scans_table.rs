//! Scans table: recent scan runs with per-run status + counts.

use veloasm::prelude::*;

use crate::state::{AppState, ScanRun, scan_status_badge};

#[component]
pub fn ScansTable() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let scans = app.scans.clone();

    view! {
        <section class="rounded-xl border border-slate-800 bg-slate-900/40">
            <div class="px-4 py-3 border-b border-slate-800">
                <h2 class="text-sm font-bold text-slate-200 uppercase tracking-wide">"Scan History"</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead>
                        <tr class="text-left text-slate-500 border-b border-slate-800">
                            <th class="px-4 py-2 font-medium">"ID"</th>
                            <th class="px-4 py-2 font-medium">"Target"</th>
                            <th class="px-4 py-2 font-medium">"Status"</th>
                            <th class="px-4 py-2 font-medium text-right">"Hosts"</th>
                            <th class="px-4 py-2 font-medium text-right">"Up"</th>
                            <th class="px-4 py-2 font-medium text-right">"Ports"</th>
                            <th class="px-4 py-2 font-medium text-right">"Vulns"</th>
                            <th class="px-4 py-2 font-medium text-right">"Duration"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/60">
                        {
                            for s in scans key = |s: &ScanRun| s.id {
                                <ScanRow run={ s.clone() } />
                            }
                        }
                    </tbody>
                </table>
            </div>
        </section>
    }
}

#[component]
fn ScanRow(run: ScanRun) -> DomNode {
    let dur = if run.duration_ms > 0 {
        format!("{:.1}s", run.duration_ms as f64 / 1000.0)
    } else {
        "—".to_string()
    };
    let badge = scan_status_badge(&run.status).to_string();
    view! {
        <tr class="hover:bg-slate-800/30">
            <td class="px-4 py-2 font-mono text-slate-400">{ run.id }</td>
            <td class="px-4 py-2 text-slate-200">{ run.target_name.clone() }</td>
            <td class="px-4 py-2">
                <span class={ format!("inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase {}", badge) }>
                    { run.status.clone() }
                </span>
            </td>
            <td class="px-4 py-2 text-right font-mono text-slate-300">{ run.hosts_scanned }</td>
            <td class="px-4 py-2 text-right font-mono text-slate-300">{ run.hosts_up }</td>
            <td class="px-4 py-2 text-right font-mono text-slate-300">{ run.ports_found }</td>
            <td class="px-4 py-2 text-right font-mono text-slate-300">{ run.vulns_found }</td>
            <td class="px-4 py-2 text-right font-mono text-slate-400">{ dur }</td>
        </tr>
    }
}
