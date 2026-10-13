# GritScan — Proactive Attack Surface Scanner

A vulnerability management and attack surface scanner built on GritShield. GritScan
finds the open doors before an attacker hits them — scheduled or manual network
sweeps, port audits, and configuration compliance checks across your fleet.

```
GritScan (this)                  GritIRT (existing)              LuxShield (existing)
┌──────────────┐  POST /api/v1/alerts     ┌──────────────────┐    MCP add_firewall_rule    ┌──────────────┐
│ Scanner      │ ──────────────────────────>│ Correlation      │ ──────────────────────────>│ XDP block    │
│ (port audit, │  source: "gritscan"        │ + Playbook       │                             │              │
│  compliance) │  kind: "vulnerability_    │   1. block (gate)│                             │              │
│              │         discovered"        │   2. ticket ─────┼──────────────────────────>│ GritJira    │
│              │                            │                  │   POST /api/v1/issues       │              │
└──────────────┘                            └──────────────────┘                             └──────────────┘
```

## Layout

```
GritScan/
├── backend/          → GritShield + SeaORM/SQLite backend
│   └── src/: api, db, mcp, middleware, scanner, state, types, main
├── frontend/         → Veloasm WASM console (Trunk + Tailwind)
├── docs/api.md       → Full API contract
└── README.md
```

## Quick start

```bash
# backend (defaults to http://127.0.0.1:8050)
cd backend && cargo run

# frontend console (Trunk dev server, hot reload)
cd frontend && trunk serve --open
```

Defaults: `http://127.0.0.1:8050`, SQLite file `gritscan.db`, API open.

### Environment variables

| Env var | Default | Meaning |
|---|---|---|
| `GS_BIND` | `127.0.0.1` | Bind address |
| `GS_PORT` | `8050` | Bind port |
| `GS_DATABASE_URL` | `sqlite://gritscan.db?mode=rwc` | SQLite file URL |
| `GS_API_KEY` | unset (open) | Require `X-API-Key` / `?api_key=` |
| `GS_IRT_URL` | unset | GritIRT base URL for alert forwarding |
| `GS_IRT_API_KEY` | unset | API key for GritIRT |

### API surface

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | Liveness + vulnerability stats |
| `/api/v1/targets` | POST | Register a scan target |
| `/api/v1/targets` | GET | List scan targets |
| `/api/v1/targets/:id` | DELETE | Remove a target |
| `/api/v1/scans` | POST | Start a scan |
| `/api/v1/scans` | GET | List scan runs |
| `/api/v1/scans/:id` | GET | Get scan run |
| `/api/v1/vulnerabilities` | GET | List vulnerabilities |
| `/api/v1/vulnerabilities/stats` | GET | Vulnerability statistics |
| `/api/v1/vulnerabilities/:id` | GET | Get vulnerability |
| `/api/v1/vulnerabilities/:id/status` | POST | Update status |
| `/api/v1/attack-surface` | GET | Attack surface summary |
| `/api/v1/compliance/rules` | GET | List compliance rules |
| `/api/v1/config` | GET/POST | Scan configuration |
| `/api/v1/stream` | GET | SSE feed |
| `/mcp` | POST | MCP tools |

### MCP tools

| Tool | Purpose |
|---|---|
| `add_target` | Register a scan target |
| `run_scan` | Trigger a scan |
| `list_vulnerabilities` | List vulnerabilities |
| `get_vulnerability` | Get vulnerability details |
| `update_vulnerability_status` | Update status |
| `get_attack_surface` | Attack surface summary |
| `list_scan_targets` | List targets |
| `get_vulnerability_stats` | Statistics |

### Integration with GritIRT

When `GS_IRT_URL` is set, GritScan automatically forwards critical/high
vulnerability alerts to GritIRT's `POST /api/v1/alerts` endpoint. GritIRT
correlates them into incidents and can auto-trigger playbooks that:
1. Block the exposed host via LuxShield MCP (`add_firewall_rule`)
2. File a remediation ticket in GritJira (`POST /api/v1/issues`)

### Compliance rules

Default rules check for common misconfigurations:
- Telnet (23) must be closed
- FTP (21) must be closed
- SMBv1 (445) must not be exposed
- RDP (3389) must not be exposed to 0.0.0.0/0
- Redis (6379) must not be exposed
- MongoDB (27017) must not be exposed
- Elasticsearch (9200) must not be exposed

Built with [GritShield](https://github.com/digiator42/GritShield) (v0.3.1, crates.io).
