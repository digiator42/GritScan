# GritScan API contract

Backend: GritShield attack surface scanner at `backend/`. Port **8050** by default
(`GS_PORT`), bind `127.0.0.1` (`GS_BIND`). All endpoints are JSON.
When `GS_API_KEY` is set, every request must present the key via the
`X-API-Key` header or `?api_key=` query parameter.

GritScan is the proactive posture component of the SOC flow. It scans the fleet
for open ports, exposed services, and compliance violations, then forwards
critical findings to GritIRT for incident correlation and automated response.

---

## Data model

### Scan Target

```json
{
  "id": 1,
  "name": "web-servers",
  "cidr": "10.0.0.0/24",
  "ports": [80, 443, 8080],
  "enabled": true,
  "created_at": 1720524000000
}
```

### Scan Run

```json
{
  "id": 5,
  "target_id": 1,
  "target_name": "web-servers",
  "status": "completed",
  "hosts_scanned": 254,
  "hosts_up": 12,
  "ports_found": 34,
  "vulns_found": 7,
  "started_at": 1720524000000,
  "finished_at": 1720524060000,
  "duration_ms": 60000,
  "error": ""
}
```

`status` ∈ `pending | running | completed | failed`.

### Vulnerability

```json
{
  "id": 42,
  "scan_id": 5,
  "target_id": 1,
  "target_name": "web-servers",
  "host": "10.0.0.15",
  "port": 6379,
  "service": "redis",
  "vuln_type": "default_creds",
  "severity": "critical",
  "title": "Redis exposed — no authentication",
  "description": "Port 6379 (Redis) is open. Redis defaults to no authentication...",
  "remediation": "Enable AUTH, bind to localhost, or restrict via firewall.",
  "cve": "CWE-306",
  "cvss": 9.8,
  "status": "open",
  "first_seen_ms": 1720524000000.0,
  "last_seen_ms": 1720524000000.0,
  "alert_sent": true,
  "created_at": 1720524000000
}
```

`severity` ∈ `low | medium | high | critical`.
`status` ∈ `open | acknowledged | remediated | false_positive`.
`vuln_type` ∈ `open_port | unpatched_service | weak_ssl | default_creds | compliance`.

---

## Endpoints

### `GET /health`

```json
{
  "service": "gritscan-backend",
  "status": "ok",
  "db": true,
  "vulnerability_stats": { "total": 42, "open": 30, "acknowledged": 5, "remediated": 4, "false_positive": 3, "by_severity": { "critical": 5, "high": 12, "medium": 18, "low": 7 } },
  "irt_connected": true
}
```

### `POST /api/v1/targets`

Register a scan target.

```json
{ "name": "web-servers", "cidr": "10.0.0.0/24", "ports": [80, 443] }
```

`ports` may be empty to scan all well-known ports. `201`:

```json
{ "target_id": 1, "name": "web-servers", "cidr": "10.0.0.0/24" }
```

### `GET /api/v1/targets`

```json
{ "count": 2, "targets": [ { "...": "ScanTarget" } ] }
```

### `DELETE /api/v1/targets/:id`

```json
{ "deleted": true, "target_id": 1 }
```

### `POST /api/v1/scans`

Start a scan against a target.

```json
{ "target_id": 1 }
```

`202 Accepted` (scan runs in background):

```json
{ "scan_id": 5, "target_id": 1, "target_name": "web-servers", "status": "running" }
```

### `GET /api/v1/scans?limit=50`

```json
{ "count": 10, "scans": [ { "...": "ScanRun" } ] }
```

### `GET /api/v1/scans/:id`

```json
{ "scan": { "...": "ScanRun" } }
```

### `GET /api/v1/vulnerabilities?limit=&status=&severity=`

```json
{ "count": 42, "vulnerabilities": [ { "...": "Vulnerability" } ] }
```

### `GET /api/v1/vulnerabilities/stats`

```json
{ "total": 42, "open": 30, "acknowledged": 5, "remediated": 4, "false_positive": 3, "by_severity": { "critical": 5, "high": 12, "medium": 18, "low": 7 } }
```

### `GET /api/v1/vulnerabilities/:id`

```json
{ "vulnerability": { "...": "Vulnerability" } }
```

### `POST /api/v1/vulnerabilities/:id/status`

Update vulnerability status.

```json
{ "status": "acknowledged" }
```

### `GET /api/v1/attack-surface`

```json
{
  "targets": 3,
  "open_vulnerabilities": 42,
  "stats": { "...": "stats" },
  "by_service": { "redis": 5, "mongodb": 3, "rdp": 2 },
  "by_severity": { "critical": 5, "high": 12, "medium": 18, "low": 7 }
}
```

### `GET /api/v1/compliance/rules`

```json
{ "count": 8, "rules": [ { "id": 1, "name": "Block Telnet", "port": 23, "allowed": false, "severity": "critical", "enabled": true } ] }
```

### `GET /api/v1/config`

```json
{ "target_timeout_ms": 5000, "port_timeout_ms": 2000, "max_ports_per_host": 1000, "compliance_check": true, "auto_alert": true, "alert_severity_threshold": "high" }
```

### `POST /api/v1/config`

Update scan configuration. All fields optional.

```json
{ "auto_alert": false, "alert_severity_threshold": "critical" }
```

### `GET /api/v1/stream`

SSE feed of scan events. Event names: `scan_started`, `scan_completed`, `vulnerability_found`.

---

## MCP (`POST /mcp`, JSON-RPC 2.0)

### tools/list

`add_target`, `run_scan`, `list_vulnerabilities`, `get_vulnerability`,
`update_vulnerability_status`, `get_attack_surface`, `list_scan_targets`,
`get_vulnerability_stats`.

### Example — `tools/call run_scan`

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"run_scan","arguments":{"target_id":1}}}
```

### Example — `tools/call list_vulnerabilities`

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call",
 "params":{"name":"list_vulnerabilities","arguments":{"status":"open","severity":"critical","limit":10}}}
```

### prompts/get remediation_plan

Argument `vulnerability_id`. Returns a step-by-step remediation plan.

---

## GritIRT integration

When `GS_IRT_URL` is set, GritScan forwards alerts for vulnerabilities at or above
the `alert_severity_threshold` (default: `high`). The alert format matches GritIRT's
`POST /api/v1/alerts` contract:

```json
{
  "source": "gritscan",
  "kind": "vulnerability_discovered",
  "severity": "critical",
  "entity": "10.0.0.15:6379",
  "detail": {
    "vulnerability_id": 42,
    "vuln_type": "default_creds",
    "title": "Redis exposed — no authentication",
    "remediation": "Enable AUTH, bind to localhost, or restrict via firewall.",
    "cve": "CWE-306",
    "cvss": 9.8,
    "service": "redis"
  },
  "correlation_key": "gritscan:vulnerability_discovered:10.0.0.15:6379"
}
```

GritIRT correlates the alert into an incident and auto-triggers a playbook that
can block the host via LuxShield and file a ticket in GritJira.

---

## Error semantics

- `400 invalid_json` / `invalid_id` / `name_and_cidr_required` / `target_id_required` / `status_required` — malformed request.
- `401 unauthorized` — missing/bad API key.
- `404 target_not_found` / `scan_not_found` / `vulnerability_not_found`.
- `413 payload_too_large` — body over 1 MiB.
- `409 scan_already_running` — a scan is already running for this target.

---

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `GS_BIND` | `127.0.0.1` | Bind address |
| `GS_PORT` | `8050` | Listen port |
| `GS_DATABASE_URL` | `sqlite://gritscan.db?mode=rwc` | SQLite file URL |
| `GS_API_KEY` | unset (open) | Require API key |
| `GS_IRT_URL` | unset | GritIRT base URL |
| `GS_IRT_API_KEY` | unset | GritIRT API key |
