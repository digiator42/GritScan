//! Severity metric tiles — total / open / critical / high vulnerability counts.
//! The headline strip of the console.

use veloasm::prelude::*;

use crate::state::AppState;

#[component]
pub fn MetricsTiles() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let stats = app.stats;
    let surface = app.surface;

    let total = memo!(move || stats.get().total);
    let open = memo!(move || stats.get().open);
    let critical = memo!(move || stats.get().by_severity.critical);
    let high = memo!(move || stats.get().by_severity.high);
    let targets = memo!(move || surface.get().targets);

    view! {
        <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div class="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
                <div class="text-[10px] uppercase tracking-[2px] text-slate-500">"TARGETS"</div>
                <div class="text-2xl font-bold mt-1 text-slate-200">{ targets }</div>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
                <div class="text-[10px] uppercase tracking-[2px] text-slate-500">"TOTAL VULNS"</div>
                <div class="text-2xl font-bold mt-1 text-slate-200">{ total }</div>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
                <div class="text-[10px] uppercase tracking-[2px] text-slate-500">"OPEN"</div>
                <div class="text-2xl font-bold mt-1 text-rose-400">{ open }</div>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
                <div class="text-[10px] uppercase tracking-[2px] text-slate-500">"CRITICAL"</div>
                <div class="text-2xl font-bold mt-1 text-rose-400">{ critical }</div>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
                <div class="text-[10px] uppercase tracking-[2px] text-slate-500">"HIGH"</div>
                <div class="text-2xl font-bold mt-1 text-orange-400">{ high }</div>
            </div>
        </div>
    }
}
