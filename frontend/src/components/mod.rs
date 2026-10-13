//! Presentational + stateful components for the GritScan console.
//!
//! Each is annotated with `#[component]`. Shared state is never threaded as
//! props — components pull the single `AppState` out of context with
//! `use_context`. Styling is Tailwind utilities; every class string is a full
//! literal so the Tailwind scanner sees it.
//!
//! Note: the `#[component]` macro resolves child components within the same
//! module scope, so a parent and its sub-components live in the same file
//! (e.g. `top_bar.rs` owns both `TopBar` and `KeyBar`).

pub mod attack_surface;
pub mod compliance;
pub mod config_panel;
pub mod metrics_tiles;
pub mod scans_table;
pub mod targets_panel;
pub mod toast_stack;
pub mod top_bar;
pub mod vuln_drawer;
pub mod vulns_table;

pub use attack_surface::*;
pub use compliance::*;
pub use config_panel::*;
pub use metrics_tiles::*;
pub use scans_table::*;
pub use targets_panel::*;
pub use toast_stack::*;
pub use top_bar::*;
pub use vuln_drawer::*;
pub use vulns_table::*;
