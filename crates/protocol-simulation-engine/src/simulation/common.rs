//! 仿真运行器通用数据结构与日志上报工具。

use protocol_simulation_common::{BoundEndpoint, SimulationRuntimeEvent};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, warn};

const REPORT_QUEUE_CAPACITY: usize = 1_024;
const REPORT_CONCURRENCY: usize = 4;
const REPORT_ATTEMPTS: usize = 3;

static REPORTER: OnceLock<mpsc::Sender<QueuedLog>> = OnceLock::new();
static REPORTER_CONTEXT: OnceLock<ReporterContext> = OnceLock::new();
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

/// 仿真交互审计日志上报草稿。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimLogDraft {
    pub rule_id: String,
    pub node_id: String,
    pub client_ip: String,
    pub client_port: u16,
    pub server_port: u16,
    pub event_type: String, // 'connection', 'http_request', 'exploit_attempt'
    pub detail_summary: String,
    pub payload_hex: Option<String>,
}

#[derive(Debug, Clone)]
struct QueuedLog {
    draft: SimLogDraft,
    endpoint_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ReporterContext {
    callback_url: String,
    callback_token: String,
    instance_id: String,
    endpoints: Vec<BoundEndpoint>,
}

pub(crate) fn initialize_reporter(
    callback_url: String,
    callback_token: String,
    instance_id: String,
    endpoints: Vec<BoundEndpoint>,
) -> anyhow::Result<()> {
    REPORTER_CONTEXT
        .set(ReporterContext {
            callback_url,
            callback_token,
            instance_id,
            endpoints,
        })
        .map_err(|_| anyhow::anyhow!("simulation audit reporter was already initialized"))
}

/// 异步向控制端上报审计日志的辅助方法。
pub(super) fn report_sim_log_async(callback_url: String, draft: SimLogDraft) {
    queue_sim_log(callback_url, draft, None);
}

pub(super) fn report_sim_log_for_endpoint_async(
    callback_url: String,
    draft: SimLogDraft,
    endpoint_id: String,
) {
    queue_sim_log(callback_url, draft, Some(endpoint_id));
}

fn queue_sim_log(callback_url: String, draft: SimLogDraft, endpoint_id: Option<String>) {
    let reporter = REPORTER.get_or_init(|| start_reporter(callback_url));
    match reporter.try_send(QueuedLog { draft, endpoint_id }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            let dropped = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped.is_multiple_of(100) {
                warn!(
                    dropped_count = dropped,
                    "simulation audit report queue is full; dropping events"
                );
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            error!("simulation audit reporter is unavailable");
        }
    }
}

/// 启动共享 HTTP 客户端和有界上报队列。
fn start_reporter(callback_url: String) -> mpsc::Sender<QueuedLog> {
    let (sender, receiver) = mpsc::channel(REPORT_QUEUE_CAPACITY);
    let context = REPORTER_CONTEXT.get().cloned().unwrap_or(ReporterContext {
        callback_url,
        callback_token: String::new(),
        instance_id: "unknown".to_string(),
        endpoints: Vec::new(),
    });
    tokio::spawn(run_reporter(context, receiver));
    sender
}

/// 以固定并发度消费审计事件，避免为每条事件创建无界 HTTP 任务。
async fn run_reporter(context: ReporterContext, mut receiver: mpsc::Receiver<QueuedLog>) {
    let client = reqwest::Client::new();
    let mut requests = JoinSet::new();

    loop {
        tokio::select! {
            result = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = result {
                    error!(error = %error, "simulation audit report task failed");
                }
            }
            queued = receiver.recv(), if requests.len() < REPORT_CONCURRENCY => {
                let Some(queued) = queued else {
                    break;
                };
                let client = client.clone();
                let context = context.clone();
                requests.spawn(async move {
                    let draft = queued.draft;
                    let endpoint_id = queued.endpoint_id.unwrap_or_else(|| context
                        .endpoints
                        .iter()
                        .find(|endpoint| endpoint.container_port == draft.server_port)
                        .map(|endpoint| endpoint.endpoint_id.clone())
                        .unwrap_or_else(|| "main".to_string()));
                    let mut metadata = BTreeMap::new();
                    metadata.insert("ruleId".to_string(), Value::String(draft.rule_id));
                    metadata.insert("nodeId".to_string(), Value::String(draft.node_id));
                    metadata.insert(
                        "serverPort".to_string(),
                        Value::Number(draft.server_port.into()),
                    );
                    let event = SimulationRuntimeEvent {
                        schema_version: 1,
                        event_id: uuid::Uuid::now_v7().to_string(),
                        instance_id: context.instance_id,
                        endpoint_id,
                        event_type: draft.event_type,
                        summary: draft.detail_summary,
                        client_ip: draft.client_ip,
                        client_port: draft.client_port,
                        metadata,
                        payload_hex: draft.payload_hex,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                    };
                    for attempt in 0..REPORT_ATTEMPTS {
                        let mut request = client.post(&context.callback_url).json(&event);
                        if !context.callback_token.is_empty() {
                            request = request.bearer_auth(&context.callback_token);
                        }
                        match request.send().await {
                            Ok(response) if response.status().is_success() => break,
                            Ok(response) if response.status().is_client_error() => {
                                warn!(
                                    status = %response.status(),
                                    event_id = %event.event_id,
                                    "suite API rejected simulation audit log"
                                );
                                break;
                            }
                            Ok(response) if attempt + 1 == REPORT_ATTEMPTS => {
                                warn!(
                                    status = %response.status(),
                                    event_id = %event.event_id,
                                    "suite API did not accept simulation audit log after retries"
                                );
                            }
                            Err(error) if attempt + 1 == REPORT_ATTEMPTS => {
                                error!(
                                    error = %error,
                                    event_id = %event.event_id,
                                    "failed to report simulation audit log after retries"
                                );
                            }
                            Ok(_) | Err(_) => {
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    100 * (1 << attempt),
                                ))
                                .await;
                            }
                        }
                    }
                });
            }
        }
    }

    while let Some(result) = requests.join_next().await {
        if let Err(error) = result {
            error!(error = %error, "simulation audit report task failed");
        }
    }
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
