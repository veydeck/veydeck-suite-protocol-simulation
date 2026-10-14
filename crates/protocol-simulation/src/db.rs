use super::models::{AuditLog, EventRequest, Instance, InstanceEndpoint, Rule, RulePackageSummary};
use super::rule_package::ImportedRulePackage;
use anyhow::{Context, anyhow};
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::fmt;
use tokio::sync::{mpsc, oneshot};

const AUDIT_LOG_QUEUE_CAPACITY: usize = 4_096;
const AUDIT_LOG_BATCH_SIZE: usize = 128;

#[derive(Debug, Clone, sqlx::FromRow)]
struct InstanceRow {
    id: String,
    rule_id: String,
    rule_name: String,
    protocol: String,
    callback_token: String,
    status: String,
    workload_id: Option<String>,
    error_message: Option<String>,
    pcap_status: String,
    pcap_start_time: Option<i64>,
    pcap_capture_id: Option<String>,
    pcap_file_path: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct AuditLogRow {
    id: i64,
    event_id: String,
    instance_id: String,
    endpoint_id: String,
    event_type: String,
    summary: String,
    client_ip: String,
    client_port: i64,
    payload_hex: Option<String>,
    metadata_json: String,
    timestamp: String,
}

impl AuditLogRow {
    fn into_log(self) -> anyhow::Result<AuditLog> {
        Ok(AuditLog {
            id: self.id,
            event_id: self.event_id,
            instance_id: self.instance_id,
            endpoint_id: self.endpoint_id,
            event_type: self.event_type,
            summary: self.summary,
            client_ip: self.client_ip,
            client_port: self.client_port,
            payload_hex: self.payload_hex,
            metadata: serde_json::from_str(&self.metadata_json)
                .context("failed to decode audit log metadata")?,
            timestamp: self.timestamp,
        })
    }
}

/// 将并发审计事件串行化并按批次写入 SQLite。
#[derive(Clone)]
pub struct AuditLogWriter {
    sender: mpsc::Sender<AuditLogWriteRequest>,
}

struct AuditLogWriteRequest {
    event: EventRequest,
    response: oneshot::Sender<Result<AuditLog, AuditLogWriteError>>,
}

#[derive(Debug)]
pub enum AuditLogWriteError {
    InstanceNotFound,
    Internal(anyhow::Error),
}

impl fmt::Display for AuditLogWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstanceNotFound => formatter.write_str("simulation instance not found"),
            Self::Internal(error) => write!(formatter, "{error:#}"),
        }
    }
}

impl std::error::Error for AuditLogWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InstanceNotFound => None,
            Self::Internal(error) => Some(error.as_ref()),
        }
    }
}

impl AuditLogWriter {
    /// 启动单写者后台任务，避免多个 SQLite 连接竞争写锁。
    pub fn start(db: SqlitePool, max_logs_per_instance: usize) -> Self {
        let (sender, receiver) = mpsc::channel(AUDIT_LOG_QUEUE_CAPACITY);
        tokio::spawn(run_audit_log_writer(db, receiver, max_logs_per_instance));
        Self { sender }
    }

    /// 将一条审计事件加入有界队列并等待事务提交结果。
    pub async fn write(&self, event: EventRequest) -> Result<AuditLog, AuditLogWriteError> {
        let (response, result) = oneshot::channel();
        self.sender
            .send(AuditLogWriteRequest { event, response })
            .await
            .map_err(|_| {
                AuditLogWriteError::Internal(anyhow!("audit log writer is unavailable"))
            })?;
        result.await.map_err(|error| {
            AuditLogWriteError::Internal(
                anyhow!(error).context("audit log writer stopped before returning a result"),
            )
        })?
    }
}

/// 持续收集当前已排队事件，并以有限批次提交到数据库。
async fn run_audit_log_writer(
    db: SqlitePool,
    mut receiver: mpsc::Receiver<AuditLogWriteRequest>,
    max_logs_per_instance: usize,
) {
    let mut instance_counts = HashMap::new();
    while let Some(first) = receiver.recv().await {
        let mut requests = Vec::with_capacity(AUDIT_LOG_BATCH_SIZE);
        requests.push(first);
        while requests.len() < AUDIT_LOG_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(request) => requests.push(request),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let mut grouped = HashMap::<String, Vec<AuditLogWriteRequest>>::new();
        for request in requests {
            grouped
                .entry(request.event.instance_id.clone())
                .or_default()
                .push(request);
        }

        for (instance_id, requests) in grouped {
            let events = requests
                .iter()
                .map(|request| &request.event)
                .collect::<Vec<_>>();
            let cached_count = instance_counts.get(&instance_id).copied();
            match insert_instance_log_batch(
                &db,
                &instance_id,
                &events,
                max_logs_per_instance,
                cached_count,
            )
            .await
            {
                Ok((logs, retained_count)) => {
                    instance_counts.insert(instance_id, retained_count);
                    for (request, log) in requests.into_iter().zip(logs) {
                        let _ = request.response.send(Ok(log));
                    }
                }
                Err(AuditLogWriteError::InstanceNotFound) => {
                    instance_counts.remove(&instance_id);
                    for request in requests {
                        let _ = request
                            .response
                            .send(Err(AuditLogWriteError::InstanceNotFound));
                    }
                }
                Err(AuditLogWriteError::Internal(error)) => {
                    let detail = format!("{error:#}");
                    for request in requests {
                        let _ = request
                            .response
                            .send(Err(AuditLogWriteError::Internal(anyhow!(detail.clone()))));
                    }
                }
            }
        }
    }
}

pub async fn init(db: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            default_port INTEGER NOT NULL,
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS rule_packages (
            package_id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            ruleset_format_version INTEGER NOT NULL,
            min_veydeck_version TEXT NOT NULL,
            rule_count INTEGER NOT NULL,
            generated_at TEXT NOT NULL,
            imported_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS instances (
            id TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            callback_token TEXT NOT NULL,
            status TEXT NOT NULL,
            workload_id TEXT,
            error_message TEXT,
            pcap_status TEXT NOT NULL DEFAULT 'idle',
            pcap_start_time INTEGER,
            pcap_capture_id TEXT,
            pcap_file_path TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            FOREIGN KEY(rule_id) REFERENCES rules(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS instance_endpoints (
            instance_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            transport TEXT NOT NULL CHECK (transport IN ('tcp', 'udp')),
            host_port INTEGER NOT NULL,
            container_port INTEGER NOT NULL,
            PRIMARY KEY(instance_id, endpoint_id),
            FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            instance_id TEXT NOT NULL,
            endpoint_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            client_port INTEGER NOT NULL,
            payload_hex TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL,
            FOREIGN KEY(instance_id) REFERENCES instances(id) ON DELETE CASCADE
        );
        "#,
    )
    .execute(db)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_instances_status ON instances(status);")
        .execute(db)
        .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_endpoint_binding ON instance_endpoints(transport, host_port);",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_logs_instance_id ON audit_logs(instance_id, id DESC);",
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_rules(db: &SqlitePool) -> anyhow::Result<Vec<Rule>> {
    sqlx::query_as::<_, Rule>(
        "SELECT id, name, protocol, default_port, config_json, created_at, updated_at FROM rules ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
    .context("failed to list rules")
}

pub async fn get_rule(db: &SqlitePool, id: &str) -> anyhow::Result<Option<Rule>> {
    sqlx::query_as::<_, Rule>(
        "SELECT id, name, protocol, default_port, config_json, created_at, updated_at FROM rules WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to fetch rule")
}

pub async fn get_current_rule_package(
    db: &SqlitePool,
) -> anyhow::Result<Option<RulePackageSummary>> {
    sqlx::query_as::<_, RulePackageSummary>(
        r#"
        SELECT package_id, version, ruleset_format_version, min_veydeck_version,
               rule_count, generated_at, imported_at
          FROM rule_packages
         ORDER BY imported_at DESC
         LIMIT 1
        "#,
    )
    .fetch_optional(db)
    .await
    .context("failed to fetch current rule package")
}

pub async fn import_rule_package(
    db: &SqlitePool,
    package: &ImportedRulePackage,
) -> anyhow::Result<RulePackageSummary> {
    let mut tx = db.begin().await.context("failed to begin rule import")?;
    let imported_at = chrono::Utc::now().to_rfc3339();

    let imported_rule_ids = package
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<HashSet<_>>();
    for rule in &package.rules {
        let config_json = rule_config_with_name_en(&rule.config_json, &rule.name_en)?;
        sqlx::query(
            r#"
            INSERT INTO rules (id, name, protocol, default_port, config_json, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                protocol = excluded.protocol,
                default_port = excluded.default_port,
                config_json = excluded.config_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.protocol)
        .bind(i64::from(rule.default_port))
        .bind(&config_json)
        .bind(&imported_at)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to import rule {}", rule.id))?;
    }

    let previous_rule_ids =
        sqlx::query_scalar::<_, String>("SELECT id FROM rules WHERE id LIKE 'sim-rule-%'")
            .fetch_all(&mut *tx)
            .await
            .context("failed to list previous packaged rules")?;
    for rule_id in previous_rule_ids {
        if imported_rule_ids.contains(rule_id.as_str()) {
            continue;
        }
        sqlx::query(
            r#"
            DELETE FROM rules
             WHERE id = ?1
               AND NOT EXISTS (SELECT 1 FROM instances WHERE rule_id = ?1)
            "#,
        )
        .bind(&rule_id)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("failed to remove stale packaged rule {rule_id}"))?;
    }

    sqlx::query(
        r#"
        INSERT INTO rule_packages (
            package_id, version, ruleset_format_version, min_veydeck_version,
            rule_count, generated_at, imported_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(package_id) DO UPDATE SET
            version = excluded.version,
            ruleset_format_version = excluded.ruleset_format_version,
            min_veydeck_version = excluded.min_veydeck_version,
            rule_count = excluded.rule_count,
            generated_at = excluded.generated_at,
            imported_at = excluded.imported_at
        "#,
    )
    .bind(&package.package_id)
    .bind(&package.version)
    .bind(package.ruleset_format_version)
    .bind(&package.min_veydeck_version)
    .bind(package.rules.len() as i64)
    .bind(&package.generated_at)
    .bind(&imported_at)
    .execute(&mut *tx)
    .await
    .context("failed to record rule package")?;

    tx.commit().await.context("failed to commit rule import")?;
    get_current_rule_package(db)
        .await?
        .context("imported rule package was not found")
}

fn rule_config_with_name_en(config_json: &str, name_en: &str) -> anyhow::Result<String> {
    let mut value = serde_json::from_str::<serde_json::Value>(config_json)
        .context("failed to parse imported rule config metadata")?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "nameEn".to_string(),
            serde_json::Value::String(name_en.to_string()),
        );
    }
    serde_json::to_string_pretty(&value).context("failed to encode imported rule config metadata")
}

pub async fn insert_rule(
    db: &SqlitePool,
    id: &str,
    name: &str,
    protocol: &str,
    default_port: u16,
    config_json: &str,
) -> anyhow::Result<Rule> {
    sqlx::query(
        r#"
        INSERT INTO rules (id, name, protocol, default_port, config_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(protocol)
    .bind(i64::from(default_port))
    .bind(config_json)
    .execute(db)
    .await
    .context("failed to insert rule")?;
    get_rule(db, id)
        .await?
        .context("inserted rule was not found")
}

pub async fn delete_rule(db: &SqlitePool, id: &str) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM rules WHERE id = ?1")
        .bind(id)
        .execute(db)
        .await
        .context("failed to delete rule")?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_instances(db: &SqlitePool) -> anyhow::Result<Vec<Instance>> {
    let rows = sqlx::query_as::<_, InstanceRow>(
        r#"
        SELECT id, rule_id, rule_name, protocol, callback_token, status, workload_id,
               error_message, pcap_status, pcap_start_time, pcap_capture_id, pcap_file_path,
               created_at, updated_at
          FROM instances
         ORDER BY created_at DESC
        "#,
    )
    .fetch_all(db)
    .await
    .context("failed to list instances")?;
    let mut instances = Vec::with_capacity(rows.len());
    for row in rows {
        instances.push(hydrate_instance(db, row).await?);
    }
    Ok(instances)
}

pub async fn list_pcap_file_paths(db: &SqlitePool) -> anyhow::Result<HashSet<String>> {
    sqlx::query_scalar::<_, String>(
        "SELECT pcap_file_path FROM instances WHERE pcap_file_path IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .context("failed to list referenced pcap files")
    .map(|files| files.into_iter().collect())
}

pub async fn insert_instance_if_port_available(
    db: &SqlitePool,
    instance: &Instance,
) -> anyhow::Result<bool> {
    let mut transaction = db
        .begin()
        .await
        .context("failed to begin instance insert")?;
    for endpoint in &instance.endpoints {
        let occupied = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1
                  FROM instance_endpoints endpoint
                  JOIN instances instance ON instance.id = endpoint.instance_id
                 WHERE endpoint.transport = ?1
                   AND endpoint.host_port = ?2
                   AND instance.status IN ('deploying', 'running')
            )
            "#,
        )
        .bind(&endpoint.transport)
        .bind(endpoint.host_port)
        .fetch_one(&mut *transaction)
        .await
        .context("failed to check endpoint availability")?;
        if occupied {
            transaction.rollback().await?;
            return Ok(false);
        }
    }
    sqlx::query(
        r#"
        INSERT INTO instances (
            id, rule_id, rule_name, protocol, callback_token,
            status, workload_id, error_message, pcap_status, pcap_start_time, pcap_capture_id, pcap_file_path,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        "#,
    )
    .bind(&instance.id)
    .bind(&instance.rule_id)
    .bind(&instance.rule_name)
    .bind(&instance.protocol)
    .bind(&instance.callback_token)
    .bind(&instance.status)
    .bind(&instance.workload_id)
    .bind(&instance.error_message)
    .bind(&instance.pcap_status)
    .bind(instance.pcap_start_time)
    .bind(&instance.pcap_capture_id)
    .bind(&instance.pcap_file_path)
    .bind(&instance.created_at)
    .bind(&instance.updated_at)
    .execute(&mut *transaction)
    .await
    .context("failed to insert instance")?;
    for endpoint in &instance.endpoints {
        sqlx::query(
            r#"
            INSERT INTO instance_endpoints (
                instance_id, endpoint_id, transport, host_port, container_port
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(&instance.id)
        .bind(&endpoint.endpoint_id)
        .bind(&endpoint.transport)
        .bind(endpoint.host_port)
        .bind(endpoint.container_port)
        .execute(&mut *transaction)
        .await
        .context("failed to insert instance endpoint")?;
    }
    transaction
        .commit()
        .await
        .context("failed to commit instance insert")?;
    Ok(true)
}

pub async fn get_instance(db: &SqlitePool, id: &str) -> anyhow::Result<Option<Instance>> {
    let row = sqlx::query_as::<_, InstanceRow>(
        r#"
        SELECT id, rule_id, rule_name, protocol, callback_token, status, workload_id,
               error_message, pcap_status, pcap_start_time, pcap_capture_id, pcap_file_path,
               created_at, updated_at
          FROM instances
         WHERE id = ?1
        "#,
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .context("failed to fetch instance")?;
    match row {
        Some(row) => Ok(Some(hydrate_instance(db, row).await?)),
        None => Ok(None),
    }
}

async fn hydrate_instance(db: &SqlitePool, row: InstanceRow) -> anyhow::Result<Instance> {
    let endpoints = sqlx::query_as::<_, InstanceEndpoint>(
        r#"
        SELECT instance_id, endpoint_id, transport, host_port, container_port
          FROM instance_endpoints
         WHERE instance_id = ?1
         ORDER BY endpoint_id
        "#,
    )
    .bind(&row.id)
    .fetch_all(db)
    .await
    .context("failed to list instance endpoints")?;
    Ok(Instance {
        id: row.id,
        rule_id: row.rule_id,
        rule_name: row.rule_name,
        protocol: row.protocol,
        endpoints,
        callback_token: row.callback_token,
        status: row.status,
        workload_id: row.workload_id,
        error_message: row.error_message,
        pcap_status: row.pcap_status,
        pcap_start_time: row.pcap_start_time,
        pcap_capture_id: row.pcap_capture_id,
        pcap_file_path: row.pcap_file_path,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

pub async fn delete_instance(db: &SqlitePool, id: &str) -> anyhow::Result<bool> {
    let result = sqlx::query("DELETE FROM instances WHERE id = ?1")
        .bind(id)
        .execute(db)
        .await
        .context("failed to delete instance")?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_instance_status(
    db: &SqlitePool,
    id: &str,
    status: &str,
    workload_id: Option<&str>,
    error_message: Option<&str>,
) -> anyhow::Result<Option<Instance>> {
    sqlx::query(
        r#"
        UPDATE instances
           SET status = ?2,
               workload_id = COALESCE(?3, workload_id),
               error_message = ?4,
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(workload_id)
    .bind(error_message)
    .execute(db)
    .await
    .context("failed to update instance")?;
    get_instance(db, id).await
}

pub async fn update_pcap_state(
    db: &SqlitePool,
    id: &str,
    pcap_status: &str,
    pcap_start_time: Option<i64>,
    pcap_capture_id: Option<&str>,
    pcap_file_path: Option<&str>,
) -> anyhow::Result<Option<Instance>> {
    sqlx::query(
        r#"
        UPDATE instances
           SET pcap_status = ?2,
               pcap_start_time = ?3,
               pcap_capture_id = ?4,
               pcap_file_path = ?5,
               updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(pcap_status)
    .bind(pcap_start_time)
    .bind(pcap_capture_id)
    .bind(pcap_file_path)
    .execute(db)
    .await
    .context("failed to update pcap state")?;
    get_instance(db, id).await
}

async fn insert_instance_log_batch(
    db: &SqlitePool,
    instance_id: &str,
    events: &[&EventRequest],
    max_logs_per_instance: usize,
    cached_count: Option<usize>,
) -> Result<(Vec<AuditLog>, usize), AuditLogWriteError> {
    let mut transaction = db
        .begin()
        .await
        .context("failed to begin audit log batch")
        .map_err(AuditLogWriteError::Internal)?;
    let instance_exists =
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM instances WHERE id = ?1)")
            .bind(instance_id)
            .fetch_one(&mut *transaction)
            .await
            .context("failed to validate audit log instance")
            .map_err(AuditLogWriteError::Internal)?;
    if !instance_exists {
        return Err(AuditLogWriteError::InstanceNotFound);
    }

    let current_count = match cached_count {
        Some(count) => count,
        None => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs WHERE instance_id = ?1")
                .bind(instance_id)
                .fetch_one(&mut *transaction)
                .await
                .context("failed to count instance audit logs")
                .map_err(AuditLogWriteError::Internal)? as usize
        }
    };
    let mut logs = Vec::with_capacity(events.len());
    let mut inserted_count = 0usize;
    for event in events {
        let timestamp = event
            .timestamp
            .clone()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let metadata_json = serde_json::to_string(&event.metadata)
            .context("failed to encode audit log metadata")
            .map_err(AuditLogWriteError::Internal)?;
        let inserted = sqlx::query(
            r#"
            INSERT OR IGNORE INTO audit_logs (
                event_id, instance_id, endpoint_id, event_type, summary, client_ip, client_port,
                payload_hex, metadata_json, timestamp
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
        )
        .bind(&event.event_id)
        .bind(instance_id)
        .bind(&event.endpoint_id)
        .bind(&event.event_type)
        .bind(&event.summary)
        .bind(&event.client_ip)
        .bind(i64::from(event.client_port))
        .bind(&event.payload_hex)
        .bind(metadata_json)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await
        .context("failed to insert audit log")
        .map_err(AuditLogWriteError::Internal)?;
        inserted_count += inserted.rows_affected() as usize;
        let log = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT id, event_id, instance_id, endpoint_id, event_type, summary, client_ip,
                   client_port, payload_hex, metadata_json, timestamp
              FROM audit_logs
             WHERE event_id = ?1
            "#,
        )
        .bind(&event.event_id)
        .fetch_one(&mut *transaction)
        .await
        .context("failed to fetch persisted audit log")
        .map_err(AuditLogWriteError::Internal)?;
        logs.push(log.into_log().map_err(AuditLogWriteError::Internal)?);
    }

    let total_count = current_count.saturating_add(inserted_count);
    let overflow = total_count.saturating_sub(max_logs_per_instance);
    if overflow > 0 {
        sqlx::query(
            r#"
            DELETE FROM audit_logs
             WHERE id IN (
                SELECT id
                  FROM audit_logs
                 WHERE instance_id = ?1
                 ORDER BY id ASC
                 LIMIT ?2
             )
            "#,
        )
        .bind(instance_id)
        .bind(i64::try_from(overflow).unwrap_or(i64::MAX))
        .execute(&mut *transaction)
        .await
        .context("failed to prune instance audit logs")
        .map_err(AuditLogWriteError::Internal)?;
    }
    transaction
        .commit()
        .await
        .context("failed to commit audit log batch")
        .map_err(AuditLogWriteError::Internal)?;
    Ok((logs, total_count.min(max_logs_per_instance)))
}

pub async fn list_instance_logs(
    db: &SqlitePool,
    instance_id: &str,
    page: u32,
    page_size: u32,
) -> anyhow::Result<(i64, Vec<AuditLog>)> {
    let total =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs WHERE instance_id = ?1")
            .bind(instance_id)
            .fetch_one(db)
            .await
            .context("failed to count instance audit logs")?;
    let offset = i64::from(page.saturating_sub(1)) * i64::from(page_size);
    let records = sqlx::query_as::<_, AuditLogRow>(
        r#"
        SELECT id, event_id, instance_id, endpoint_id, event_type, summary, client_ip, client_port,
               payload_hex, metadata_json, timestamp
          FROM audit_logs
         WHERE instance_id = ?1
         ORDER BY id DESC
         LIMIT ?2 OFFSET ?3
        "#,
    )
    .bind(instance_id)
    .bind(i64::from(page_size))
    .bind(offset)
    .fetch_all(db)
    .await
    .context("failed to list instance audit logs")?;
    Ok((
        total,
        records
            .into_iter()
            .map(AuditLogRow::into_log)
            .collect::<anyhow::Result<Vec<_>>>()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(instance_id: &str, index: usize) -> EventRequest {
        EventRequest {
            schema_version: 1,
            event_id: format!("event-{instance_id}-{index}"),
            instance_id: instance_id.to_string(),
            endpoint_id: "main".to_string(),
            event_type: "connection".to_string(),
            summary: format!("event {index}"),
            client_ip: "192.0.2.1".to_string(),
            client_port: 12_345,
            payload_hex: None,
            metadata: serde_json::json!({"index": index}),
            timestamp: None,
        }
    }

    fn instance(id: &str, port: i64) -> Instance {
        Instance {
            id: id.to_string(),
            rule_id: "rule-1".to_string(),
            rule_name: "HTTP simulation".to_string(),
            protocol: "http".to_string(),
            endpoints: vec![InstanceEndpoint {
                instance_id: id.to_string(),
                endpoint_id: "main".to_string(),
                transport: "tcp".to_string(),
                host_port: port,
                container_port: 80,
            }],
            callback_token: "test-token".to_string(),
            status: "deploying".to_string(),
            workload_id: None,
            error_message: None,
            pcap_status: "idle".to_string(),
            pcap_start_time: None,
            pcap_capture_id: None,
            pcap_file_path: None,
            created_at: "2026-07-13T00:00:00Z".to_string(),
            updated_at: "2026-07-13T00:00:00Z".to_string(),
        }
    }

    async fn insert_rule_and_instance(db: &SqlitePool, instance_id: &str, port: i64) {
        sqlx::query(
            "INSERT OR IGNORE INTO rules (id, name, protocol, default_port, config_json) \
             VALUES ('rule-1', 'HTTP simulation', 'http', 8080, '{}')",
        )
        .execute(db)
        .await
        .unwrap();
        assert!(
            insert_instance_if_port_available(db, &instance(instance_id, port))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn init_creates_empty_rule_table() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        let rules = list_rules(&db).await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn audit_log_writer_serializes_concurrent_events() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        insert_rule_and_instance(&db, "instance-1", 8080).await;
        let writer = AuditLogWriter::start(db.clone(), 10_000);
        let mut writes = tokio::task::JoinSet::new();

        for index in 0..256 {
            let writer = writer.clone();
            writes.spawn(async move { writer.write(event("instance-1", index)).await });
        }
        while let Some(result) = writes.join_next().await {
            result.unwrap().unwrap();
        }

        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 256);
    }

    #[tokio::test]
    async fn audit_log_retention_keeps_latest_ten_thousand_per_instance() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        insert_rule_and_instance(&db, "instance-1", 8080).await;

        let mut count = None;
        for start in (0..10_001).step_by(AUDIT_LOG_BATCH_SIZE) {
            let events = (start..(start + AUDIT_LOG_BATCH_SIZE).min(10_001))
                .map(|index| event("instance-1", index))
                .collect::<Vec<_>>();
            let references = events.iter().collect::<Vec<_>>();
            let (_, retained_count) =
                insert_instance_log_batch(&db, "instance-1", &references, 10_000, count)
                    .await
                    .unwrap();
            count = Some(retained_count);
        }

        let summaries = sqlx::query_scalar::<_, String>(
            "SELECT summary FROM audit_logs WHERE instance_id = 'instance-1' ORDER BY id ASC",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(summaries.len(), 10_000);
        assert_eq!(summaries.first().unwrap(), "event 1");
        assert_eq!(summaries.last().unwrap(), "event 10000");
    }

    #[tokio::test]
    async fn deleting_instance_cascades_audit_logs() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        insert_rule_and_instance(&db, "instance-1", 8080).await;
        let event = event("instance-1", 1);
        insert_instance_log_batch(&db, "instance-1", &[&event], 10_000, None)
            .await
            .unwrap();

        delete_instance(&db, "instance-1").await.unwrap();

        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn missing_instance_does_not_block_other_instance_batch() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        insert_rule_and_instance(&db, "instance-1", 8080).await;
        let writer = AuditLogWriter::start(db.clone(), 10_000);

        let (missing, existing) = tokio::join!(
            writer.write(event("missing", 1)),
            writer.write(event("instance-1", 2)),
        );

        assert!(matches!(missing, Err(AuditLogWriteError::InstanceNotFound)));
        assert_eq!(existing.unwrap().summary, "event 2");
    }

    #[tokio::test]
    async fn instance_audit_logs_are_paginated_in_stable_order() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        insert_rule_and_instance(&db, "instance-1", 8080).await;
        let events = (0..5)
            .map(|index| event("instance-1", index))
            .collect::<Vec<_>>();
        let references = events.iter().collect::<Vec<_>>();
        insert_instance_log_batch(&db, "instance-1", &references, 10_000, None)
            .await
            .unwrap();

        let (total, records) = list_instance_logs(&db, "instance-1", 2, 2).await.unwrap();

        assert_eq!(total, 5);
        assert_eq!(
            records
                .iter()
                .map(|record| record.summary.as_str())
                .collect::<Vec<_>>(),
            vec!["event 2", "event 1"]
        );
    }

    #[tokio::test]
    async fn duplicate_event_id_is_idempotent() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        insert_rule_and_instance(&db, "instance-1", 8080).await;
        let event = event("instance-1", 1);
        let first = insert_instance_log_batch(&db, "instance-1", &[&event], 10_000, None)
            .await
            .unwrap();
        let second = insert_instance_log_batch(&db, "instance-1", &[&event], 10_000, Some(first.1))
            .await
            .unwrap();

        assert_eq!(first.0[0].id, second.0[0].id);
        assert_eq!(second.1, 1);
    }

    #[tokio::test]
    async fn active_instance_reserves_host_port_until_terminal_state() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO rules (id, name, protocol, default_port, config_json) \
             VALUES ('rule-1', 'HTTP simulation', 'http', 8080, '{}')",
        )
        .execute(&db)
        .await
        .unwrap();

        assert!(
            insert_instance_if_port_available(&db, &instance("instance-1", 8080))
                .await
                .unwrap()
        );
        assert!(
            !insert_instance_if_port_available(&db, &instance("instance-2", 8080))
                .await
                .unwrap()
        );
        assert!(
            insert_instance_if_port_available(&db, &instance("instance-3", 8081))
                .await
                .unwrap()
        );

        update_instance_status(&db, "instance-1", "error", None, Some("failed"))
            .await
            .unwrap();
        assert!(
            insert_instance_if_port_available(&db, &instance("instance-2", 8080))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn tcp_and_udp_can_share_the_same_numeric_host_port() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO rules (id, name, protocol, default_port, config_json) \
             VALUES ('rule-1', 'DNS simulation', 'dns', 1053, '{}')",
        )
        .execute(&db)
        .await
        .unwrap();

        let mut tcp = instance("dns-tcp-instance", 1053);
        tcp.protocol = "dns".to_string();
        assert!(insert_instance_if_port_available(&db, &tcp).await.unwrap());

        let mut udp = instance("dns-udp-instance", 1053);
        udp.protocol = "dns".to_string();
        udp.endpoints[0].transport = "udp".to_string();
        assert!(insert_instance_if_port_available(&db, &udp).await.unwrap());
    }

    #[tokio::test]
    async fn rule_package_refresh_does_not_orphan_running_workloads() {
        let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
        init(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO rules (id, name, protocol, default_port, config_json) \
             VALUES ('sim-rule-9', 'Old rule', 'http', 80, '{}')",
        )
        .execute(&db)
        .await
        .unwrap();
        let mut active = instance("instance-1", 8080);
        active.rule_id = "sim-rule-9".to_string();
        active.rule_name = "Old rule".to_string();
        assert!(
            insert_instance_if_port_available(&db, &active)
                .await
                .unwrap()
        );

        import_rule_package(
            &db,
            &ImportedRulePackage {
                package_id: "veydeck-sim-rules".to_string(),
                version: "0.1.0-alpha.1".to_string(),
                ruleset_format_version: 1,
                min_veydeck_version: "0.1.0-alpha.1".to_string(),
                generated_at: "2026-08-11T00:00:00Z".to_string(),
                rules: Vec::new(),
            },
        )
        .await
        .unwrap();

        assert!(get_instance(&db, "instance-1").await.unwrap().is_some());
        assert!(get_rule(&db, "sim-rule-9").await.unwrap().is_some());
    }
}
