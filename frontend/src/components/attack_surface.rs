//! Attack surface panel: service breakdown (bar chart) + severity distribution.

use veloasm::prelude::*;

use crate::state::AppState;

#[derive(Clone)]
struct ServiceRow {
    name: String,
    count: i64,
    pct: i64,
}

#[component]
pub fn AttackSurface() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let surface = app.surface;

    // Rows live in a local SignalVec so the view's `for` can iterate them.
    let rows: SignalVec<ServiceRow> = signal_vec(Vec::new());

    // Recompute rows whenever the attack surface changes.
    let rows_calc = rows.clone();
    create_effect(move || {
        let sf = surface.get();
        let mut v: Vec<(String, i64)> =
            sf.by_service.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        let max = v.iter().map(|(_, c)| *c).max().unwrap_or(1).max(1);
        let computed: Vec<ServiceRow> = v
            .into_iter()
            .map(|(name, count)| {
                let pct = ((count as f64 / max as f64) * 100.0).round() as i64;
                ServiceRow { name, count, pct }
            })
            .collect();
        rows_calc.with_mut(|r| *r = computed);
    });

    let open = memo!(move || surface.get().open_vulnerabilities);
    let crit = memo!(move || surface.get().by_severity.critical);
    let high = memo!(move || surface.get().by_severity.high);
    let med = memo!(move || surface.get().by_severity.medium);
    let low = memo!(move || surface.get().by_severity.low);

    view! {
        <section class="rounded-xl border border-slate-800 bg-slate-900/40">
            <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-sm font-bold text-slate-200 uppercase tracking-wide">"Attack Surface"</h2>
                <span class="text-xs text-slate-400">{ format!("{} open", open.get()) }</span>
            </div>
            <div class="p-4 grid gap-4 md:grid-cols-2">
                <div>
                    <div class="text-[10px] uppercase tracking-wide text-slate-500 mb-2">"By service"</div>
                    <div class="space-y-1.5">
                        {
                            for row in rows key = |r: &ServiceRow| r.name.clone() {
                                <ServiceBar row={ row.clone() } />
                            }
                        }
                    </div>
                </div>

                <div>
                    <div class="text-[10px] uppercase tracking-wide text-slate-500 mb-2">"By severity"</div>
                    <div class="grid grid-cols-4 gap-2">
                        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-2 py-2 text-center">
                            <div class="text-[9px] uppercase tracking-wide text-slate-500">"CRIT"</div>
                            <div class="text-lg font-bold mt-0.5 text-rose-400">{ crit }</div>
                        </div>
                        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-2 py-2 text-center">
                            <div class="text-[9px] uppercase tracking-wide text-slate-500">"HIGH"</div>
                            <div class="text-lg font-bold mt-0.5 text-orange-400">{ high }</div>
                        </div>
                        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-2 py-2 text-center">
                            <div class="text-[9px] uppercase tracking-wide text-slate-500">"MED"</div>
                            <div class="text-lg font-bold mt-0.5 text-amber-400">{ med }</div>
                        </div>
                        <div class="rounded-lg border border-slate-800 bg-slate-950/50 px-2 py-2 text-center">
                            <div class="text-[9px] uppercase tracking-wide text-slate-500">"LOW"</div>
                            <div class="text-lg font-bold mt-0.5 text-sky-400">{ low }</div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    }
}

#[component]
fn ServiceBar(row: ServiceRow) -> DomNode {
    let width = format!("{}%", row.pct);
    let count_txt = row.count.to_string();
    view! {
        <div class="flex items-center gap-2 text-xs">
            <span class="w-20 font-mono text-slate-400 truncate">{ row.name.clone() }</span>
            <div class="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden">
                <div class="h-full bg-indigo-500" style:width={ width }></div>
            </div>
            <span class="w-6 text-right font-mono text-slate-300">{ count_txt }</span>
        </div>
    }
}
