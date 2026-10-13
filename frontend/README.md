# GritScan Frontend

Reactive Rust→WASM dashboard for the GritScan attack-surface scanner, built
with [Veloasm](https://github.com/digiator42/Veloasm) + Tailwind CSS.

Standalone crate (excluded from any workspace so host builds never resolve
wasm deps). Mirrors the layout proven in `admin-command-center/frontend`.

## Run

```bash
# backend first (defaults to http://127.0.0.1:8050)
cd ../backend && cargo run

# frontend dev server (Trunk, hot reload, Tailwind)
trunk serve --open

# production bundle -> dist/
trunk build --release
```

Then open the Trunk URL (default http://localhost:8080).

## Stack

- `veloasm` (v0.1.1 from crates.io, feature `json`) — fine-grained
  reactive SPA framework, no virtual DOM.
- Tailwind v3 via Trunk's `tailwind-css` pipeline (`input.css` +
  `tailwind.config.js`; `content` scans `src/**/*.rs`).
- `web-sys`, `wasm-bindgen`, `gloo-timers`, `serde`.

## What it shows

- **Metric tiles** — targets, total / open / critical / high vulnerabilities
  (from `/health` + `/api/v1/vulnerabilities/stats`).
- **Attack surface** — open-vuln count, service breakdown bars, severity cells
  (`/api/v1/attack-surface`).
- **Scan targets** — register / delete targets, kick a scan (`Run Scan`)
  (`/api/v1/targets`, `POST /api/v1/scans`).
- **Scan history** — recent runs with counts + duration (`/api/v1/scans`).
- **Vulnerabilities** — status + severity filters, each row opens a detail
  drawer with remediation and a status workflow
  (`/api/v1/vulnerabilities[/:id][/status]`).
- **Compliance rules** — the scanner's built-in checks
  (`/api/v1/compliance/rules`).
- **Scan configuration** — timeouts, auto-alert, alert threshold
  (`/api/v1/config`).
- **Live SSE** feed (`/api/v1/stream`) + a 10 s REST poll.

## Auth

The backend is open by default. When `GS_API_KEY` is set, paste the key into
the top-bar field; it is held in memory only and sent as `X-API-Key`
(`?api_key=` on the SSE, which can't set headers).

## Layout

```
src/
  lib.rs              entry point (provide AppState, start poll + SSE, mount)
  state.rs            AppState (one struct of signals) + typed models + helpers
  api.rs              backend contract (typed request/reply wrappers)
  net.rs              SSE connect + 10 s poll refresh
  components/
    top_bar.rs        TopBar + KeyBar (API-key control)
    metrics_tiles.rs  headline count strip
    attack_surface.rs service bars + severity cells
    targets_panel.rs  register/delete targets, Run Scan
    scans_table.rs    scan history
    vulns_table.rs    filterable vuln list
    vuln_drawer.rs    detail drawer + status workflow
    compliance.rs     compliance rules table
    config_panel.rs   scan configuration form
    toast_stack.rs    transient action feedback
```

Built with [GritShield](https://github.com/digiator42/GritShield) on the
backend and [Veloasm](https://github.com/digiator42/Veloasm) on the frontend.
