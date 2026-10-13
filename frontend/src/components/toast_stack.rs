//! Toast stack — transient feedback for actions (scan started, target added,
//! status updated). Mirrors the ACC console's toast UX.

use gloo_timers::future::TimeoutFuture;
use veloasm::prelude::*;

use crate::state::{AppState, TOAST_KEEP, TOAST_TTL_MS, Toast};

/// Push a toast and schedule its auto-dismiss.
pub fn push_toast(app: &AppState, title: String, detail: String, bad: bool) {
    let id = app.next_toast_id();
    app.toasts.with_mut(|v| {
        v.push(Toast {
            id,
            title,
            detail,
            bad,
        });
        while v.len() > TOAST_KEEP {
            v.remove(0);
        }
    });

    let toasts = app.toasts.clone();
    wasm_bindgen_futures::spawn_local(async move {
        TimeoutFuture::new(TOAST_TTL_MS).await;
        toasts.with_mut(|v| {
            if let Some(pos) = v.iter().position(|t| t.id == id) {
                v.remove(pos);
            }
        });
    });
}

#[component]
pub fn ToastStack() -> DomNode {
    let app = use_context::<AppState>().expect("AppState must be provided before mounting");
    let toasts = app.toasts.clone();

    view! {
        <div class="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-80">
            {
                for t in toasts key = |t: &Toast| t.id {
                    <ToastCard toast={ t.clone() } />
                }
            }
        </div>
    }
}

#[component]
fn ToastCard(toast: Toast) -> DomNode {
    let border = if toast.bad {
        "border-rose-500/40"
    } else {
        "border-slate-700"
    };
    let title_color = if toast.bad {
        "text-rose-300"
    } else {
        "text-slate-200"
    };
    view! {
        <div class={ format!("toast-in rounded-lg border {} bg-slate-900/90 px-4 py-3 shadow-lg backdrop-blur", border) }>
            <div class={ format!("text-sm font-semibold {}", title_color) }>{ toast.title.clone() }</div>
            <div class="text-xs text-slate-400 mt-0.5 break-words">{ toast.detail.clone() }</div>
        </div>
    }
}
