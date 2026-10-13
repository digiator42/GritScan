use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect,
};

use crate::types::{
    ComplianceRule, ScanConfig, ScanRun, ScanTarget, Vulnerability,
};

pub async fn init_tables(db: &DatabaseConnection) -> Result<(), String> {
    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS scan_targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL DEFAULT '',
            cidr        TEXT NOT NULL DEFAULT '',
            ports       TEXT NOT NULL DEFAULT '[]',
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  INTEGER NOT NULL
        );",
    )
    .await?;

    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS scan_runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id     INTEGER NOT NULL DEFAULT 0,
            target_name   TEXT NOT NULL DEFAULT '',
            status        TEXT NOT NULL DEFAULT 'pending',
            hosts_scanned INTEGER NOT NULL DEFAULT 0,
            hosts_up      INTEGER NOT NULL DEFAULT 0,
            ports_found   INTEGER NOT NULL DEFAULT 0,
            vulns_found   INTEGER NOT NULL DEFAULT 0,
            started_at    INTEGER NOT NULL DEFAULT 0,
            finished_at   INTEGER NOT NULL DEFAULT 0,
            duration_ms   INTEGER NOT NULL DEFAULT 0,
            error         TEXT NOT NULL DEFAULT ''
        );",
    )
    .await?;

    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS vulnerabilities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER NOT NULL DEFAULT 0,
            target_id       INTEGER NOT NULL DEFAULT 0,
            target_name     TEXT NOT NULL DEFAULT '',
            host            TEXT NOT NULL DEFAULT '',
            port            INTEGER NOT NULL DEFAULT 0,
            service         TEXT NOT NULL DEFAULT '',
            vuln_type       TEXT NOT NULL DEFAULT '',
            severity        TEXT NOT NULL DEFAULT 'medium',
            title           TEXT NOT NULL DEFAULT '',
            description     TEXT NOT NULL DEFAULT '',
            remediation     TEXT NOT NULL DEFAULT '',
            cve             TEXT,
            cvss            REAL,
            status          TEXT NOT NULL DEFAULT 'open',
            first_seen_ms   REAL NOT NULL,
            last_seen_ms    REAL NOT NULL,
            alert_sent      INTEGER NOT NULL DEFAULT 0,
            created_at      INTEGER NOT NULL
        );",
    )
    .await?;

    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS compliance_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            port        INTEGER NOT NULL DEFAULT 0,
            allowed     INTEGER NOT NULL DEFAULT 1,
            severity    TEXT NOT NULL DEFAULT 'medium',
            enabled     INTEGER NOT NULL DEFAULT 1
        );",
    )
    .await?;

    run_sql(
        db,
        "CREATE TABLE IF NOT EXISTS scan_config (
            id                      INTEGER PRIMARY KEY CHECK (id = 1),
            target_timeout_ms       INTEGER NOT NULL DEFAULT 5000,
            port_timeout_ms         INTEGER NOT NULL DEFAULT 2000,
            max_ports_per_host      INTEGER NOT NULL DEFAULT 1000,
            compliance_check        INTEGER NOT NULL DEFAULT 1,
            auto_alert              INTEGER NOT NULL DEFAULT 1,
            alert_severity_threshold TEXT NOT NULL DEFAULT 'high'
        );",
    )
    .await?;

    // Insert default config if not present
    run_sql(
        db,
        "INSERT OR IGNORE INTO scan_config (id) VALUES (1);",
    )
    .await?;

    // Insert default compliance rules
    let defaults = vec![
        ("Block Telnet", "Port 23 (Telnet) must be closed", 23, 0, "critical"),
        ("Block FTP", "Port 21 (FTP) must be closed", 21, 0, "high"),
        ("Block SMBv1", "Port 445 (SMB) should not expose SMBv1", 445, 0, "high"),
        ("HTTPS required", "Port 443 (HTTPS) should be open on web servers", 443, 1, "medium"),
        ("Block RDP exposure", "Port 3389 (RDP) must not be exposed to 0.0.0.0/0", 3389, 0, "critical"),
        ("Block Redis", "Port 6379 (Redis) must not be exposed", 6379, 0, "critical"),
        ("Block MongoDB", "Port 27017 (MongoDB) must not be exposed", 27017, 0, "critical"),
        ("Block Elasticsearch", "Port 9200 (Elasticsearch) must not be exposed", 9200, 0, "high"),
    ];
    for (name, desc, port, allowed, sev) in defaults {
        run_sql(
            db,
            &format!(
                "INSERT OR IGNORE INTO compliance_rules (name, description, port, allowed, severity)
                 SELECT '{name}', '{desc}', {port}, {allowed}, '{sev}'
                 WHERE NOT EXISTS (SELECT 1 FROM compliance_rules WHERE port = {port});"
            ),
        )
        .await?;
    }

    Ok(())
}

async fn run_sql(db: &DatabaseConnection, sql: &str) -> Result<(), String> {
    db.execute(sea_orm::Statement::from_string(db.get_database_backend(), sql.to_string()))
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn ping(db: &DatabaseConnection) -> Result<(), String> {
    run_sql(db, "SELECT 1").await
}

// ---------------------------------------------------------------------------
// Scan Targets
// ---------------------------------------------------------------------------

pub async fn insert_target(
    db: &DatabaseConnection,
    name: &str,
    cidr: &str,
    ports: &[u16],
) -> Result<i64, String> {
    let ports_json = serde_json::to_string(ports).unwrap_or_else(|_| "[]".to_string());
    let row = scan_targets::ActiveModel {
        id: NotSet,
        name: Set(name.to_string()),
        cidr: Set(cidr.to_string()),
        ports: Set(ports_json),
        enabled: Set(1),
        created_at: Set(crate::types::now_ms_i64()),
    };
    let inserted = row.insert(db).await.map_err(|e| e.to_string())?;
    Ok(inserted.id as i64)
}

pub async fn list_targets(db: &DatabaseConnection) -> Result<Vec<ScanTarget>, String> {
    let rows = scan_targets::Entity::find()
        .order_by_desc(scan_targets::Column::Id)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_target).collect())
}

pub async fn find_target(db: &DatabaseConnection, id: i64) -> Result<Option<ScanTarget>, String> {
    let row = scan_targets::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(row.map(to_target))
}

pub async fn delete_target(db: &DatabaseConnection, id: i64) -> Result<(), String> {
    scan_targets::Entity::delete_by_id(id as i32)
        .exec(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn to_target(row: scan_targets::Model) -> ScanTarget {
    let ports: Vec<u16> = serde_json::from_str(&row.ports).unwrap_or_default();
    ScanTarget {
        id: row.id as i64,
        name: row.name,
        cidr: row.cidr,
        ports,
        enabled: row.enabled != 0,
        created_at: row.created_at,
    }
}

// ---------------------------------------------------------------------------
// Scan Runs
// ---------------------------------------------------------------------------

pub async fn insert_run(
    db: &DatabaseConnection,
    target_id: i64,
    target_name: &str,
) -> Result<i64, String> {
    let row = scan_runs::ActiveModel {
        id: NotSet,
        target_id: Set(target_id),
        target_name: Set(target_name.to_string()),
        status: Set("running".to_string()),
        hosts_scanned: Set(0),
        hosts_up: Set(0),
        ports_found: Set(0),
        vulns_found: Set(0),
        started_at: Set(crate::types::now_ms_i64()),
        finished_at: Set(0),
        duration_ms: Set(0),
        error: Set(String::new()),
    };
    let inserted = row.insert(db).await.map_err(|e| e.to_string())?;
    Ok(inserted.id as i64)
}

pub async fn update_run(
    db: &DatabaseConnection,
    id: i64,
    status: &str,
    hosts_scanned: i64,
    hosts_up: i64,
    ports_found: i64,
    vulns_found: i64,
    error: &str,
) -> Result<(), String> {
    let model = scan_runs::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "run_not_found".to_string())?;

    let now = crate::types::now_ms_i64();
    let duration = now - model.started_at;

    let mut active: scan_runs::ActiveModel = model.into();
    active.status = Set(status.to_string());
    active.hosts_scanned = Set(hosts_scanned);
    active.hosts_up = Set(hosts_up);
    active.ports_found = Set(ports_found);
    active.vulns_found = Set(vulns_found);
    active.finished_at = Set(now);
    active.duration_ms = Set(duration);
    active.error = Set(error.to_string());
    active.update(db).await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn list_runs(
    db: &DatabaseConnection,
    limit: u64,
) -> Result<Vec<ScanRun>, String> {
    let rows = scan_runs::Entity::find()
        .order_by_desc(scan_runs::Column::Id)
        .limit(limit)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_run).collect())
}

pub async fn find_run(db: &DatabaseConnection, id: i64) -> Result<Option<ScanRun>, String> {
    let row = scan_runs::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(row.map(to_run))
}

fn to_run(row: scan_runs::Model) -> ScanRun {
    ScanRun {
        id: row.id as i64,
        target_id: row.target_id,
        target_name: row.target_name,
        status: row.status,
        hosts_scanned: row.hosts_scanned,
        hosts_up: row.hosts_up,
        ports_found: row.ports_found,
        vulns_found: row.vulns_found,
        started_at: row.started_at,
        finished_at: row.finished_at,
        duration_ms: row.duration_ms,
        error: row.error,
    }
}

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

pub async fn insert_vulnerability(
    db: &DatabaseConnection,
    vuln: &Vulnerability,
) -> Result<i64, String> {
    let row = vulnerabilities::ActiveModel {
        id: NotSet,
        scan_id: Set(vuln.scan_id),
        target_id: Set(vuln.target_id),
        target_name: Set(vuln.target_name.clone()),
        host: Set(vuln.host.clone()),
        port: Set(vuln.port as i32),
        service: Set(vuln.service.clone()),
        vuln_type: Set(vuln.vuln_type.clone()),
        severity: Set(vuln.severity.clone()),
        title: Set(vuln.title.clone()),
        description: Set(vuln.description.clone()),
        remediation: Set(vuln.remediation.clone()),
        cve: Set(vuln.cve.clone()),
        cvss: Set(vuln.cvss),
        status: Set(vuln.status.clone()),
        first_seen_ms: Set(vuln.first_seen_ms),
        last_seen_ms: Set(vuln.last_seen_ms),
        alert_sent: Set(if vuln.alert_sent { 1 } else { 0 }),
        created_at: Set(crate::types::now_ms_i64()),
    };
    let inserted = row.insert(db).await.map_err(|e| e.to_string())?;
    Ok(inserted.id as i64)
}

pub async fn list_vulnerabilities(
    db: &DatabaseConnection,
    limit: u64,
    status: Option<&str>,
    severity: Option<&str>,
) -> Result<Vec<Vulnerability>, String> {
    let mut q = vulnerabilities::Entity::find().order_by_desc(vulnerabilities::Column::Id);
    if let Some(s) = status {
        q = q.filter(vulnerabilities::Column::Status.eq(s));
    }
    if let Some(s) = severity {
        q = q.filter(vulnerabilities::Column::Severity.eq(s.to_string()));
    }
    let rows = q.limit(limit).all(db).await.map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_vuln).collect())
}

pub async fn find_vulnerability(
    db: &DatabaseConnection,
    id: i64,
) -> Result<Option<Vulnerability>, String> {
    let row = vulnerabilities::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(row.map(to_vuln))
}

pub async fn update_vuln_status(
    db: &DatabaseConnection,
    id: i64,
    status: &str,
) -> Result<Vulnerability, String> {
    let model = vulnerabilities::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "vulnerability_not_found".to_string())?;
    let mut active: vulnerabilities::ActiveModel = model.into();
    active.status = Set(status.to_string());
    let row = active.update(db).await.map_err(|e| e.to_string())?;
    Ok(to_vuln(row))
}

pub async fn mark_alert_sent(db: &DatabaseConnection, id: i64) -> Result<(), String> {
    let model = vulnerabilities::Entity::find_by_id(id as i32)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "vulnerability_not_found".to_string())?;
    let mut active: vulnerabilities::ActiveModel = model.into();
    active.alert_sent = Set(1);
    active.update(db).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Count vulnerabilities by status.
pub async fn vuln_stats(
    db: &DatabaseConnection,
) -> Result<serde_json::Value, String> {
    let all = vulnerabilities::Entity::find()
        .all(db)
        .await
        .map_err(|e| e.to_string())?;

    let mut open = 0i64;
    let mut acknowledged = 0i64;
    let mut remediated = 0i64;
    let mut false_positive = 0i64;
    let mut critical = 0i64;
    let mut high = 0i64;
    let mut medium = 0i64;
    let mut low = 0i64;

    for v in &all {
        match v.status.as_str() {
            "open" => open += 1,
            "acknowledged" => acknowledged += 1,
            "remediated" => remediated += 1,
            "false_positive" => false_positive += 1,
            _ => {}
        }
        match v.severity.as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    Ok(serde_json::json!({
        "total": all.len(),
        "open": open,
        "acknowledged": acknowledged,
        "remediated": remediated,
        "false_positive": false_positive,
        "by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }
    }))
}

fn to_vuln(row: vulnerabilities::Model) -> Vulnerability {
    Vulnerability {
        id: row.id as i64,
        scan_id: row.scan_id,
        target_id: row.target_id,
        target_name: row.target_name,
        host: row.host,
        port: row.port as u16,
        service: row.service,
        vuln_type: row.vuln_type,
        severity: row.severity,
        title: row.title,
        description: row.description,
        remediation: row.remediation,
        cve: row.cve,
        cvss: row.cvss,
        status: row.status,
        first_seen_ms: row.first_seen_ms,
        last_seen_ms: row.last_seen_ms,
        alert_sent: row.alert_sent != 0,
        created_at: row.created_at,
    }
}

// ---------------------------------------------------------------------------
// Compliance Rules
// ---------------------------------------------------------------------------

pub async fn list_compliance_rules(
    db: &DatabaseConnection,
) -> Result<Vec<ComplianceRule>, String> {
    let rows = compliance_rules::Entity::find()
        .order_by_asc(compliance_rules::Column::Port)
        .all(db)
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows.into_iter().map(to_rule).collect())
}

fn to_rule(row: compliance_rules::Model) -> ComplianceRule {
    ComplianceRule {
        id: row.id as i64,
        name: row.name,
        description: row.description,
        port: row.port as u16,
        allowed: row.allowed != 0,
        severity: row.severity,
        enabled: row.enabled != 0,
    }
}

// ---------------------------------------------------------------------------
// Scan Config
// ---------------------------------------------------------------------------

pub async fn get_config(db: &DatabaseConnection) -> Result<ScanConfig, String> {
    let row = scan_config::Entity::find_by_id(1)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "config_not_found".to_string())?;

    Ok(ScanConfig {
        target_timeout_ms: row.target_timeout_ms as u64,
        port_timeout_ms: row.port_timeout_ms as u64,
        max_ports_per_host: row.max_ports_per_host as u32,
        compliance_check: row.compliance_check != 0,
        auto_alert: row.auto_alert != 0,
        alert_severity_threshold: row.alert_severity_threshold,
    })
}

pub async fn update_config(
    db: &DatabaseConnection,
    config: &ScanConfig,
) -> Result<(), String> {
    let model = scan_config::Entity::find_by_id(1)
        .one(db)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "config_not_found".to_string())?;

    let mut active: scan_config::ActiveModel = model.into();
    active.target_timeout_ms = Set(config.target_timeout_ms as i64);
    active.port_timeout_ms = Set(config.port_timeout_ms as i64);
    active.max_ports_per_host = Set(config.max_ports_per_host as i64);
    active.compliance_check = Set(if config.compliance_check { 1 } else { 0 });
    active.auto_alert = Set(if config.auto_alert { 1 } else { 0 });
    active.alert_severity_threshold = Set(config.alert_severity_threshold.clone());
    active.update(db).await.map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entity modules (inline to keep it simple)
// ---------------------------------------------------------------------------

mod scan_targets {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "scan_targets")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub cidr: String,
        pub ports: String,
        pub enabled: i32,
        pub created_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod scan_runs {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "scan_runs")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub target_id: i64,
        pub target_name: String,
        pub status: String,
        pub hosts_scanned: i64,
        pub hosts_up: i64,
        pub ports_found: i64,
        pub vulns_found: i64,
        pub started_at: i64,
        pub finished_at: i64,
        pub duration_ms: i64,
        pub error: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod vulnerabilities {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "vulnerabilities")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub scan_id: i64,
        pub target_id: i64,
        pub target_name: String,
        pub host: String,
        pub port: i32,
        pub service: String,
        pub vuln_type: String,
        pub severity: String,
        pub title: String,
        pub description: String,
        pub remediation: String,
        pub cve: Option<String>,
        pub cvss: Option<f64>,
        pub status: String,
        pub first_seen_ms: f64,
        pub last_seen_ms: f64,
        pub alert_sent: i32,
        pub created_at: i64,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod compliance_rules {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "compliance_rules")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub name: String,
        pub description: String,
        pub port: i32,
        pub allowed: i32,
        pub severity: String,
        pub enabled: i32,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod scan_config {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "scan_config")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub target_timeout_ms: i64,
        pub port_timeout_ms: i64,
        pub max_ports_per_host: i64,
        pub compliance_check: i32,
        pub auto_alert: i32,
        pub alert_severity_threshold: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}
