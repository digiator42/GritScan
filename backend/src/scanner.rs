use std::net::Ipv4Addr;
use std::sync::Arc;

use serde_json::json;

use crate::db;
use crate::state::AppState;
use crate::types::{
    now_ms_f64, normalize_severity, severity_rank, ComplianceRule, IrtAlert, PortFinding,
    ScanTarget, Vulnerability,
};

/// Well-known port → service mapping.
const WELL_KNOWN_PORTS: &[(u16, &str)] = &[
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "https"),
    (445, "smb"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (5900, "vnc"),
    (6379, "redis"),
    (8080, "http-proxy"),
    (8443, "https-alt"),
    (9200, "elasticsearch"),
    (27017, "mongodb"),
];

fn service_name(port: u16) -> &'static str {
    WELL_KNOWN_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, s)| *s)
        .unwrap_or("unknown")
}

/// Parse a CIDR string into a list of host IPs (limited to /24 or larger).
fn expand_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("invalid CIDR: {cidr}"));
    }
    let base: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("invalid IP: {}", parts[0]))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| format!("invalid prefix: {}", parts[1]))?;

    if prefix > 24 {
        return Err("only /24 or larger subnets supported".to_string());
    }

    let base_u32 = u32::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    let network = base_u32 & mask;
    let broadcast = network | !mask;

    // Limit to 254 hosts max
    let mut hosts = Vec::new();
    for ip in (network + 1)..broadcast {
        hosts.push(Ipv4Addr::from(ip));
        if hosts.len() >= 254 {
            break;
        }
    }
    Ok(hosts)
}

/// Simulate a TCP connect scan against a single host.
/// In a real implementation this would use raw sockets or a crate like `scanrs`.
/// Here we simulate with deterministic randomness based on IP+port for demo purposes.
/// Note: no `rand::thread_rng()` because `ThreadRng` is not `Send` and this
/// function is called from `tokio::spawn` contexts.
fn scan_host(
    host: Ipv4Addr,
    ports: &[u16],
    _timeout_ms: u64,
) -> Vec<PortFinding> {
    let mut findings = Vec::new();

    for &port in ports {
        // Deterministic "open" probability based on IP hash + port
        let hash = (u32::from(host) as u64).wrapping_mul(2654435761).wrapping_add(port as u64);
        let open_prob = match port {
            22 | 80 | 443 => 0.8,  // Common services usually open
            21 | 23 | 445 => 0.3, // Legacy services sometimes open
            3306 | 5432 | 6379 | 27017 | 9200 => 0.2, // Databases sometimes exposed
            3389 | 5900 => 0.15,  // Remote access occasionally exposed
            _ => 0.05,
        };

        let is_open = (hash % 100) as f64 / 100.0 < open_prob;

        if is_open {
            let service = service_name(port);
            // Deterministic version string from hash
            let version = if hash % 3 == 0 {
                format!("{}.{}", (hash % 10) + 1, (hash % 20) + 1)
            } else {
                "unknown".to_string()
            };
            findings.push(PortFinding {
                port,
                service: service.to_string(),
                version,
                state: "open".to_string(),
            });
        }
    }

    findings
}

/// Check compliance rules against port findings.
fn check_compliance(
    host: Ipv4Addr,
    findings: &[PortFinding],
    rules: &[ComplianceRule],
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let open_ports: std::collections::HashSet<u16> = findings.iter().map(|f| f.port).collect();

    for rule in rules {
        if !rule.enabled {
            continue;
        }

        let is_open = open_ports.contains(&rule.port);
        let violates = if rule.allowed { !is_open } else { is_open };

        if violates {
            let severity = normalize_severity(&rule.severity);
            let title = if rule.allowed {
                format!("Missing required service on port {}", rule.port)
            } else {
                format!("Prohibited service exposed on port {}", rule.port)
            };
            let description = rule.description.clone();
            let remediation = if rule.allowed {
                format!("Enable the service on port {}", rule.port)
            } else {
                format!("Close port {} or restrict access via firewall", rule.port)
            };

            vulns.push(Vulnerability {
                id: 0,
                scan_id: 0,
                target_id: 0,
                target_name: String::new(),
                host: host.to_string(),
                port: rule.port,
                service: service_name(rule.port).to_string(),
                vuln_type: "compliance".to_string(),
                severity,
                title,
                description,
                remediation,
                cve: None,
                cvss: None,
                status: "open".to_string(),
                first_seen_ms: now_ms_f64(),
                last_seen_ms: now_ms_f64(),
                alert_sent: false,
                created_at: 0,
            });
        }
    }

    vulns
}

/// Assess vulnerabilities from open ports.
fn assess_vulnerabilities(
    host: Ipv4Addr,
    findings: &[PortFinding],
) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let ts = now_ms_f64();

    for finding in findings {
        let service = &finding.service;
        let port = finding.port;

        // Known dangerous service exposures
        let (vuln_type, severity, title, description, remediation, cve, cvss) = match service.as_str() {
            "telnet" => (
                "unpatched_service",
                "critical",
                "Telnet exposed — cleartext protocol".to_string(),
                "Port 23 (Telnet) is open. Telnet transmits credentials in cleartext and is trivially intercepted.".to_string(),
                "Disable Telnet and migrate to SSH (port 22).".to_string(),
                Some("CWE-319".to_string()),
                Some(9.8),
            ),
            "ftp" => (
                "unpatched_service",
                "high",
                "FTP exposed — cleartext authentication".to_string(),
                "Port 21 (FTP) is open. FTP transmits credentials in cleartext.".to_string(),
                "Replace with SFTP (port 22) or FTPS (port 990).".to_string(),
                Some("CWE-319".to_string()),
                Some(7.5),
            ),
            "redis" => (
                "default_creds",
                "critical",
                "Redis exposed — no authentication".to_string(),
                "Port 6379 (Redis) is open. Redis defaults to no authentication and can be exploited for RCE.".to_string(),
                "Enable AUTH, bind to localhost, or restrict via firewall.".to_string(),
                Some("CWE-306".to_string()),
                Some(9.8),
            ),
            "mongodb" => (
                "default_creds",
                "critical",
                "MongoDB exposed — no authentication".to_string(),
                "Port 27017 (MongoDB) is open. MongoDB defaults to no authentication.".to_string(),
                "Enable authentication, bind to localhost, or restrict via firewall.".to_string(),
                Some("CWE-306".to_string()),
                Some(9.8),
            ),
            "elasticsearch" => (
                "unpatched_service",
                "high",
                "Elasticsearch exposed".to_string(),
                "Port 9200 (Elasticsearch) is open. Unauthenticated Elasticsearch instances are a common target.".to_string(),
                "Enable X-Pack security or restrict access via reverse proxy.".to_string(),
                None,
                Some(7.5),
            ),
            "rdp" => (
                "unpatched_service",
                "high",
                "RDP exposed to network".to_string(),
                "Port 3389 (RDP) is open. RDP has a history of critical vulnerabilities (BlueKeep, etc.).".to_string(),
                "Restrict RDP to VPN-only access or use Network Level Authentication.".to_string(),
                Some("CWE-284".to_string()),
                Some(8.8),
            ),
            "vnc" => (
                "weak_ssl",
                "high",
                "VNC exposed — weak authentication".to_string(),
                "Port 5900 (VNC) is open. VNC uses weak authentication by default.".to_string(),
                "Tunnel VNC through SSH or use a VPN.".to_string(),
                Some("CWE-287".to_string()),
                Some(7.5),
            ),
            "smb" => (
                "unpatched_service",
                "high",
                "SMB exposed — potential SMBv1".to_string(),
                "Port 445 (SMB) is open. SMBv1 has critical vulnerabilities (EternalBlue).".to_string(),
                "Disable SMBv1 and restrict to internal network only.".to_string(),
                Some("CWE-284".to_string()),
                Some(8.8),
            ),
            "mysql" | "postgres" | "mssql" | "oracle" => (
                "unpatched_service",
                "medium",
                format!("Database ({}) exposed", service),
                format!("Port {} ({}) is open. Database ports should not be exposed to untrusted networks.", port, service),
                "Restrict database access to application servers only.".to_string(),
                None,
                Some(5.3),
            ),
            _ => continue,
        };

        vulns.push(Vulnerability {
            id: 0,
            scan_id: 0,
            target_id: 0,
            target_name: String::new(),
            host: host.to_string(),
            port,
            service: service.to_string(),
            vuln_type: vuln_type.to_string(),
            severity: severity.to_string(),
            title,
            description,
            remediation,
            cve,
            cvss,
            status: "open".to_string(),
            first_seen_ms: ts,
            last_seen_ms: ts,
            alert_sent: false,
            created_at: 0,
        });
    }

    vulns
}

/// Run a full scan against a target.
pub async fn run_scan(
    st: Arc<AppState>,
    target: &ScanTarget,
    scan_run_id: i64,
) -> Result<Vec<Vulnerability>, String> {
    let hosts = expand_cidr(&target.cidr)?;
    let ports = if target.ports.is_empty() {
        WELL_KNOWN_PORTS.iter().map(|(p, _)| *p).collect()
    } else {
        target.ports.clone()
    };

    let rules = if st.config.compliance_check {
        db::list_compliance_rules(st.db.as_ref()).await.unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut all_vulns = Vec::new();
    let mut hosts_up = 0i64;
    let mut total_ports = 0i64;

    for host in &hosts {
        let findings = scan_host(*host, &ports, st.config.port_timeout_ms);
        if !findings.is_empty() {
            hosts_up += 1;
        }
        total_ports += findings.len() as i64;

        // Assess vulnerabilities from open ports
        let mut vulns = assess_vulnerabilities(*host, &findings);
        for v in &mut vulns {
            v.scan_id = scan_run_id;
            v.target_id = target.id;
            v.target_name = target.name.clone();
        }
        all_vulns.extend(vulns);

        // Check compliance rules
        let compliance_vulns = check_compliance(*host, &findings, &rules);
        for mut v in compliance_vulns {
            v.scan_id = scan_run_id;
            v.target_id = target.id;
            v.target_name = target.name.clone();
            all_vulns.push(v);
        }
    }

    // Persist vulnerabilities and send alerts
    let mut alert_count = 0;
    for vuln in &all_vulns {
        let vid = db::insert_vulnerability(st.db.as_ref(), vuln).await?;

        // Auto-alert to GritIRT if severity meets threshold
        if st.config.auto_alert && severity_rank(&vuln.severity) >= severity_rank(&st.config.alert_severity_threshold) {
            if let Err(e) = send_irt_alert(st.clone(), vuln, vid).await {
                eprintln!("[gritscan] failed to send IRT alert for vuln {vid}: {e}");
            } else {
                let _ = db::mark_alert_sent(st.db.as_ref(), vid).await;
                alert_count += 1;
            }
        }
    }

    // Update scan run
    let _ = db::update_run(
        st.db.as_ref(),
        scan_run_id,
        "completed",
        hosts.len() as i64,
        hosts_up,
        total_ports,
        all_vulns.len() as i64,
        "",
    )
    .await;

    println!(
        "[gritscan] scan {} completed: {} hosts scanned, {} up, {} ports found, {} vulns, {} alerts sent",
        scan_run_id,
        hosts.len(),
        hosts_up,
        total_ports,
        all_vulns.len(),
        alert_count
    );

    Ok(all_vulns)
}

/// Send a vulnerability alert to GritIRT.
async fn send_irt_alert(
    st: Arc<AppState>,
    vuln: &Vulnerability,
    vuln_id: i64,
) -> Result<(), String> {
    let irt_url = st
        .irt_url
        .as_ref()
        .ok_or_else(|| "IRT URL not configured".to_string())?;

    let alert = IrtAlert {
        source: "gritscan".to_string(),
        kind: "vulnerability_discovered".to_string(),
        severity: vuln.severity.clone(),
        entity: format!("{}:{}", vuln.host, vuln.port),
        detail: json!({
            "vulnerability_id": vuln_id,
            "vuln_type": vuln.vuln_type,
            "title": vuln.title,
            "description": vuln.description,
            "remediation": vuln.remediation,
            "cve": vuln.cve,
            "cvss": vuln.cvss,
            "service": vuln.service,
            "target_name": vuln.target_name,
        }),
        ts_ms: now_ms_f64(),
        correlation_key: Some(format!(
            "gritscan:vulnerability_discovered:{}:{}",
            vuln.host, vuln.port
        )),
    };

    let url = format!("{}/api/v1/alerts", irt_url.trim_end_matches('/'));
    let mut req = st
        .client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&alert);

    if let Some(key) = &st.irt_api_key {
        req = req.header("X-API-Key", key);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("IRT request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("IRT returned {}: {}", status, body));
    }

    Ok(())
}

/// Get a summary of the attack surface.
pub async fn attack_surface_summary(
    st: Arc<AppState>,
) -> Result<serde_json::Value, String> {
    let targets = db::list_targets(st.db.as_ref()).await?;
    let vulns = db::list_vulnerabilities(st.db.as_ref(), 1000, Some("open"), None).await?;
    let stats = db::vuln_stats(st.db.as_ref()).await?;

    // Group by service
    let mut by_service: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut by_severity: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for v in &vulns {
        *by_service.entry(v.service.clone()).or_insert(0) += 1;
        *by_severity.entry(v.severity.clone()).or_insert(0) += 1;
    }

    Ok(json!({
        "targets": targets.len(),
        "open_vulnerabilities": vulns.len(),
        "stats": stats,
        "by_service": by_service,
        "by_severity": by_severity,
    }))
}
