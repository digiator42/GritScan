//! Compliance rules panel: read-only list of the scanner's built-in
//! misconfiguration checks (port must be closed / must not be exposed).

use veloasm::prelude::*;

use crate::state::{AppState, ComplianceRule, severity_text};

#[component]
pub fn Compliance() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let rules = app.rules.clone();

    view! {
        <section class="rounded-xl border border-slate-800 bg-slate-900/40">
            <div class="px-4 py-3 border-b border-slate-800">
                <h2 class="text-sm font-bold text-slate-200 uppercase tracking-wide">"Compliance Rules"</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-xs">
                    <thead>
                        <tr class="text-left text-slate-500 border-b border-slate-800">
                            <th class="px-4 py-2 font-medium">"Rule"</th>
                            <th class="px-4 py-2 font-medium">"Port"</th>
                            <th class="px-4 py-2 font-medium">"Expectation"</th>
                            <th class="px-4 py-2 font-medium">"Severity"</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/60">
                        {
                            for r in rules key = |r: &ComplianceRule| r.id {
                                <RuleRow rule={ r.clone() } />
                            }
                        }
                    </tbody>
                </table>
            </div>
        </section>
    }
}

#[component]
fn RuleRow(rule: ComplianceRule) -> DomNode {
    let expectation = if rule.allowed {
        "must be open".to_string()
    } else {
        "must be closed".to_string()
    };
    let sev_class = severity_text(&rule.severity).to_string();
    view! {
        <tr class="hover:bg-slate-800/30">
            <td class="px-4 py-2 text-slate-200">{ rule.name.clone() }</td>
            <td class="px-4 py-2 font-mono text-slate-400">{ rule.port }</td>
            <td class="px-4 py-2 text-slate-400">{ expectation }</td>
            <td class={ format!("px-4 py-2 font-semibold uppercase text-[10px] {}", sev_class) }>
                { rule.severity.clone() }
            </td>
        </tr>
    }
}
