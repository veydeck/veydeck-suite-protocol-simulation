use super::AppState;
use super::agent::{
    AgentApiError, StartWorkloadRequest, WorkloadPort, WorkloadResources, WorkloadTransport,
};
use super::db;
use super::models::{
    ApiEnvelope, AuditLogPage, CreateRuleRequest, DeployInstanceRequest, ErrorEnvelope,
    EventRequest, Instance,
};
use super::pcap;
use super::rule_package;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use protocol_simulation_common::{
    BoundEndpoint, EngineLaunchConfig, ProtocolId, TransportProtocol, protocol_descriptor,
    protocol_descriptors, validate_behavior,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;
use uuid::Uuid;
use veydeck_suite_runtime::{
    OperationEvent, OperationImpact, OperationOutcome, OperationTarget, ParameterValue,
};

type ApiResult<T> = Result<T, ApiError>;

const PCAP_MAX_DURATION_SECS: i64 = 300;
const RULE_PACKAGE_EXTENSION: &str = ".vprp";

/// 生成协议仿真动态工作负载的可读名称主体。
///
/// 名称由主端点宿主机端口、规则编号和协议仿真业务实例 ID 末 6 位组成；
/// Agent 在创建动态容器时统一添加 `veydeck-` 前缀。
fn simulation_workload_name(rule_id: &str, host_port: u16, instance_id: &str) -> String {
    let rule_identifier = rule_id
        .strip_prefix("sim-rule-")
        .or_else(|| rule_id.strip_prefix("rule-"))
        .unwrap_or(rule_id);
    let compact_instance_id = instance_id
        .chars()
        .filter(|value| value.is_ascii_alphanumeric())
        .collect::<String>();
    let short_instance_id = compact_instance_id
        .get(compact_instance_id.len().saturating_sub(6)..)
        .unwrap_or(compact_instance_id.as_str());
    format!("{host_port}-{rule_identifier}-{short_instance_id}")
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
    message_key: Option<String>,
    cause: Option<anyhow::Error>,
}

/// 组装协议仿真 API、内部回调端点和前端静态资源路由。
pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/api/capabilities", get(get_capabilities))
        .route("/api/rules", get(list_rules).post(create_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/rule-package/current", get(get_current_rule_package))
        .route("/api/rule-package/import", post(import_rule_package))
        .route("/api/instances", get(list_instances))
        .route("/api/instances/deploy", post(deploy_instance))
        .route("/api/instances/{id}/undeploy", post(undeploy_instance))
        .route("/api/instances/{id}/pcap/start", post(start_pcap))
        .route("/api/instances/{id}/pcap/stop", post(stop_pcap))
        .route("/api/instances/{id}/pcap", delete(delete_pcap))
        .route("/api/instances/{id}/pcap/download", post(download_pcap))
        .route("/api/instances/{id}/audit-logs", get(list_instance_logs))
        .route("/internal/events", post(record_event))
        .layer(DefaultBodyLimit::max(25 * 1024 * 1024));

    let frontend = ServeDir::new(&state.config.frontend_dir)
        .not_found_service(ServeFile::new(state.config.frontend_dir.join("index.html")));

    Router::new()
        .merge(api)
        .fallback_service(frontend)
        .layer(CorsLayer::permissive())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_failure(()),
        )
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": true, "service": "protocol-simulation" }))
}

/// 返回协议描述、端点定义和前端功能开关。
async fn get_capabilities() -> Json<ApiEnvelope<serde_json::Value>> {
    Json(ApiEnvelope {
        success: true,
        data: serde_json::json!({
            "schemaVersion": 1,
            "protocols": protocol_descriptors(),
            "features": {
                "multiEndpoint": true,
                "wholeWorkloadCapture": true,
                "guidedRuleEditor": true,
                "advancedJsonEditor": true
            }
        }),
    })
}

/// 列出当前规则包和用户创建的全部仿真规则。
async fn list_rules(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    let rules = db::list_rules(&state.db).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: rules,
    }))
}

/// 校验协议行为并创建用户自定义仿真规则。
async fn create_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateRuleRequest>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let protocol = parse_protocol(&payload.protocol)?;
    if payload.name.trim().is_empty() {
        return Err(ApiError::bad_request("rule name is required"));
    }
    let id = format!("rule-{}", Uuid::now_v7());
    let behavior = payload
        .config_json
        .get("behavior")
        .cloned()
        .unwrap_or_else(|| payload.config_json.clone());
    let behavior = validate_behavior(protocol, behavior)
        .map_err(|error| ApiError::bad_request(format!("invalid protocol behavior: {error}")))?;
    let config_json = serde_json::to_string_pretty(&serde_json::json!({"behavior": behavior}))
        .map_err(|err| ApiError::bad_request(format!("invalid config JSON: {err}")))?;
    let rule = db::insert_rule(
        &state.db,
        &id,
        payload.name.trim(),
        &payload.protocol,
        payload.default_port,
        &config_json,
    )
    .await?;
    emit_operation_event(
        &state,
        operation_event(
            "rule_created",
            "创建仿真规则",
            "Create simulation rule",
            "simulation_rule",
            &rule.id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: rule,
        }),
    ))
}

/// 删除指定仿真规则并记录操作审计事件。
async fn delete_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let deleted = db::delete_rule(&state.db, &id).await?;
    if !deleted {
        return Err(ApiError::not_found("rule not found"));
    }
    emit_operation_event(
        &state,
        operation_event(
            "rule_deleted",
            "删除仿真规则",
            "Delete simulation rule",
            "simulation_rule",
            &id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: serde_json::json!({ "deleted": true }),
    }))
}

/// 返回当前已导入规则包的版本和规则统计信息。
async fn get_current_rule_package(
    State(state): State<Arc<AppState>>,
) -> ApiResult<impl IntoResponse> {
    let package = db::get_current_rule_package(&state.db).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: package,
    }))
}

/// 解析并导入签名规则包，同时校验平台最低版本与规则协议。
async fn import_rule_package(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let mut archive = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::bad_request(format!("invalid multipart request: {err}")))?
    {
        if matches!(field.name(), Some("archive" | "file")) {
            let file_name = field.file_name().unwrap_or_default().to_ascii_lowercase();
            if !file_name.ends_with(RULE_PACKAGE_EXTENSION) {
                return Err(ApiError::bad_request("rule package must be .vprp"));
            }
            archive =
                Some(field.bytes().await.map_err(|err| {
                    ApiError::bad_request(format!("failed to read upload: {err}"))
                })?);
            break;
        }
    }

    let Some(archive) = archive else {
        return Err(ApiError::bad_request("rule package file is required"));
    };
    let package = rule_package::parse_rule_package(&archive)
        .map_err(|err| ApiError::bad_request(format!("invalid rule package: {err}")))?;
    let platform_version = state.agent.platform_version().await?;
    let minimum_version = semver::Version::parse(&package.min_veydeck_version)
        .map_err(|error| ApiError::bad_request(format!("invalid minVeydeckVersion: {error}")))?;
    if platform_version < minimum_version {
        return Err(ApiError::bad_request(format!(
            "rule package requires Veydeck {minimum_version} or newer; current version is {platform_version}"
        )));
    }
    for rule in &package.rules {
        parse_protocol(&rule.protocol)?;
    }
    let summary = db::import_rule_package(&state.db, &package).await?;
    emit_operation_event(
        &state,
        operation_event_builder(
            "rule_package_imported",
            "导入规则包",
            "Import rule package",
            "rule_package",
            &summary.package_id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        )
        .parameter(
            "ruleCount",
            ParameterValue::Number(summary.rule_count as f64),
        )
        .build()
        .expect("static operation event must be valid"),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: summary,
    }))
}

/// 在与 Agent 对账后返回全部协议仿真实例。
async fn list_instances(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    let instances = reconcile_instances_with_agent(&state).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: instances,
    }))
}

/// 校验规则端点、原子预留宿主机端口，并通过 Agent 部署仿真工作负载。
///
/// 数据库实例先进入 `deploying`；Agent 成功后记录 `workloadId` 并转为 `running`，
/// 端口冲突时删除预留记录，其他启动错误则保留为可诊断的 `error` 实例。
async fn deploy_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DeployInstanceRequest>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let Some(rule) = db::get_rule(&state.db, &payload.rule_id).await? else {
        return Err(ApiError::not_found("rule not found"));
    };
    let protocol = parse_protocol(&rule.protocol)?;
    let descriptor = protocol_descriptor(protocol);
    let mut requested = HashMap::new();
    for binding in payload.endpoint_bindings {
        if binding.host_port == 0 {
            return Err(ApiError::bad_request(
                "endpoint host port must be between 1 and 65535",
            ));
        }
        if requested
            .insert(binding.endpoint_id.clone(), binding.host_port)
            .is_some()
        {
            return Err(ApiError::bad_request(format!(
                "duplicate endpoint binding: {}",
                binding.endpoint_id
            )));
        }
    }
    let known = descriptor
        .endpoints
        .iter()
        .map(|endpoint| endpoint.id.as_str())
        .collect::<HashSet<_>>();
    if let Some(unknown) = requested.keys().find(|id| !known.contains(id.as_str())) {
        return Err(ApiError::bad_request(format!(
            "unknown endpoint binding: {unknown}"
        )));
    }
    let endpoints = descriptor
        .endpoints
        .iter()
        .filter_map(|endpoint| {
            requested
                .get(&endpoint.id)
                .map(|host_port| super::models::InstanceEndpoint {
                    instance_id: String::new(),
                    endpoint_id: endpoint.id.clone(),
                    transport: endpoint.transport.as_str().to_string(),
                    host_port: i64::from(*host_port),
                    container_port: i64::from(endpoint.container_port),
                })
        })
        .collect::<Vec<_>>();
    if let Some(missing) = descriptor
        .endpoints
        .iter()
        .find(|endpoint| endpoint.required && !requested.contains_key(&endpoint.id))
    {
        return Err(ApiError::bad_request(format!(
            "required endpoint binding is missing: {}",
            missing.id
        )));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let instance_id = format!("sim-{}", Uuid::now_v7());
    let callback_token = Uuid::now_v7().to_string();
    let mut instance = Instance {
        id: instance_id.clone(),
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        protocol: rule.protocol.clone(),
        endpoints: endpoints
            .into_iter()
            .map(|mut endpoint| {
                endpoint.instance_id.clone_from(&instance_id);
                endpoint
            })
            .collect(),
        callback_token: callback_token.clone(),
        status: "deploying".to_string(),
        workload_id: None,
        error_message: None,
        pcap_status: "idle".to_string(),
        pcap_start_time: None,
        pcap_capture_id: None,
        pcap_file_path: None,
        created_at: now.clone(),
        updated_at: now,
    };
    if !db::insert_instance_if_port_available(&state.db, &instance).await? {
        return Err(ApiError::conflict(
            "one or more endpoint bindings are already used by an active simulation instance",
        )
        .with_message_key("app.simulation.deployments.messages.portOccupied"));
    }

    let config_json = serde_json::from_str::<serde_json::Value>(&rule.config_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    let behavior = config_json.get("behavior").cloned().unwrap_or(config_json);
    let launch_config = EngineLaunchConfig {
        schema_version: 1,
        protocol,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        instance_id: instance_id.clone(),
        callback_url: state.config.event_callback_url.clone(),
        callback_token,
        endpoints: instance
            .endpoints
            .iter()
            .map(|endpoint| BoundEndpoint {
                endpoint_id: endpoint.endpoint_id.clone(),
                transport: if endpoint.transport == "udp" {
                    TransportProtocol::Udp
                } else {
                    TransportProtocol::Tcp
                },
                host_port: endpoint.host_port as u16,
                container_port: endpoint.container_port as u16,
            })
            .collect(),
        behavior,
    };
    let primary_host_port = instance
        .endpoints
        .first()
        .map(|endpoint| endpoint.host_port as u16)
        .ok_or_else(|| ApiError::bad_request("simulation instance requires an endpoint"))?;
    let agent_payload = StartWorkloadRequest {
        workload_kind: "simulation-rule".to_string(),
        workload_name: simulation_workload_name(&rule.id, primary_host_port, &instance_id),
        image: state.config.engine_image.clone(),
        ports: instance
            .endpoints
            .iter()
            .map(|endpoint| WorkloadPort {
                endpoint_id: endpoint.endpoint_id.clone(),
                host_port: endpoint.host_port as u16,
                container_port: endpoint.container_port as u16,
                protocol: if endpoint.transport == "udp" {
                    WorkloadTransport::Udp
                } else {
                    WorkloadTransport::Tcp
                },
            })
            .collect(),
        env: serde_json::json!({}),
        config_json: serde_json::to_value(launch_config)
            .map_err(|error| ApiError::bad_request(format!("invalid launch config: {error}")))?,
        resources: WorkloadResources {
            memory_mb: 256,
            cpu_shares: 256,
        },
    };

    match state.agent.start_workload(&agent_payload).await {
        Ok(response) => {
            let workload_id = response
                .workload_id
                .unwrap_or_else(|| format!("workload-{instance_id}"));
            instance = db::update_instance_status(
                &state.db,
                &instance_id,
                "running",
                Some(&workload_id),
                None,
            )
            .await?
            .ok_or_else(|| ApiError::not_found("instance not found after deployment"))?;
        }
        Err(err)
            if err
                .downcast_ref::<AgentApiError>()
                .is_some_and(AgentApiError::is_port_unavailable) =>
        {
            db::delete_instance(&state.db, &instance_id).await?;
            emit_operation_event(
                &state,
                operation_event_builder(
                    "instance_deployed",
                    "部署仿真实例",
                    "Deploy simulation instance",
                    "simulation_instance",
                    &instance_id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    operation_context.as_deref(),
                )
                .error("PORT_UNAVAILABLE", "Requested host port is unavailable")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
            return Err(ApiError::conflict(
                "one or more endpoint bindings are unavailable on the target node",
            )
            .with_message_key("app.simulation.deployments.messages.portOccupied"));
        }
        Err(err) => {
            let error_message = format!("{err:#}");
            instance = db::update_instance_status(
                &state.db,
                &instance_id,
                "error",
                None,
                Some(&error_message),
            )
            .await?
            .ok_or_else(|| ApiError::not_found("instance not found after deployment failure"))?;
        }
    }

    let (outcome, impact) = if instance.status == "running" {
        (OperationOutcome::Success, OperationImpact::Info)
    } else {
        (OperationOutcome::Failure, OperationImpact::Error)
    };
    let mut audit = operation_event_builder(
        "instance_deployed",
        "部署仿真实例",
        "Deploy simulation instance",
        "simulation_instance",
        &instance_id,
        (outcome, impact),
        operation_context.as_deref(),
    );
    if instance.status != "running" {
        audit = audit.error("INSTANCE_DEPLOY_FAILED", "Simulation deployment failed");
    }
    emit_operation_event(
        &state,
        audit.build().expect("static operation event must be valid"),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: instance,
        }),
    ))
}

/// 串行撤销指定仿真实例，依次回收 Agent 工作负载、PCAP 文件和数据库记录。
async fn undeploy_instance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let _guard = state.instance_lifecycle_locks.lock(&id).await;
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if let Some(workload_id) = instance.workload_id.as_deref()
        && let Err(err) = state.agent.stop_workload(workload_id).await
    {
        let error_message = format!("{err:#}");
        db::update_instance_status(
            &state.db,
            &id,
            "error",
            instance.workload_id.as_deref(),
            Some(&error_message),
        )
        .await?;
        emit_operation_event(
            &state,
            operation_event_builder(
                "instance_undeployed",
                "撤销仿真实例",
                "Undeploy simulation instance",
                "simulation_instance",
                &id,
                (OperationOutcome::Failure, OperationImpact::Error),
                operation_context.as_deref(),
            )
            .error("INSTANCE_UNDEPLOY_FAILED", "Simulation undeployment failed")
            .build()
            .expect("static operation event must be valid"),
        )
        .await;
        return Err(ApiError::from(err));
    }
    if let Err(err) =
        pcap::remove_capture_file(&state.config.data_dir, instance.pcap_file_path.as_deref()).await
    {
        let error_message = format!("{err:#}");
        db::update_instance_status(
            &state.db,
            &id,
            "error",
            instance.workload_id.as_deref(),
            Some(&error_message),
        )
        .await?;
        emit_operation_event(
            &state,
            operation_event_builder(
                "instance_undeployed",
                "撤销仿真实例",
                "Undeploy simulation instance",
                "simulation_instance",
                &id,
                (OperationOutcome::Failure, OperationImpact::Error),
                operation_context.as_deref(),
            )
            .error(
                "INSTANCE_PCAP_CLEANUP_FAILED",
                "Simulation PCAP cleanup failed",
            )
            .build()
            .expect("static operation event must be valid"),
        )
        .await;
        return Err(ApiError::from(err));
    }
    let deleted = instance;
    db::delete_instance(&state.db, &id).await?;
    emit_operation_event(
        &state,
        operation_event(
            "instance_undeployed",
            "撤销仿真实例",
            "Undeploy simulation instance",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: deleted,
    }))
}

/// 将本地活动实例与 Agent 现存工作负载对账，标记已丢失负载的实例为非活动。
///
/// Agent 列表不可用时保留本地状态，避免因短暂通信故障误判实例已停止。
async fn reconcile_instances_with_agent(state: &AppState) -> ApiResult<Vec<Instance>> {
    finalize_expired_pcap_captures(state).await;
    let instances = db::list_instances(&state.db).await?;
    let workloads = match state.agent.list_workloads().await {
        Ok(workloads) => workloads,
        Err(err) => {
            tracing::debug!("skip instance reconcile because Agent workload list failed: {err:#}");
            return Ok(instances);
        }
    };

    let workload_ids = workloads
        .into_iter()
        .filter(|workload| workload.suite_instance_id == state.config.suite_instance_id)
        .map(|workload| workload.workload_id)
        .collect::<HashSet<_>>();
    let mut reconciled = Vec::with_capacity(instances.len());
    for instance in instances {
        if should_mark_instance_inactive(&instance, &workload_ids) {
            let updated =
                db::update_instance_status(&state.db, &instance.id, "inactive", None, None)
                    .await?
                    .unwrap_or(instance);
            reconciled.push(updated);
        } else {
            reconciled.push(instance);
        }
    }
    Ok(reconciled)
}

/// 判断处于部署中或运行中的实例是否已丢失对应 Agent 工作负载。
fn should_mark_instance_inactive(instance: &Instance, workload_ids: &HashSet<String>) -> bool {
    matches!(instance.status.as_str(), "deploying" | "running")
        && instance
            .workload_id
            .as_ref()
            .is_some_and(|workload_id| !workload_ids.contains(workload_id))
}

/// 串行启动指定运行实例的整负载抓包，并安排超时自动停止任务。
async fn start_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let _guard = state.instance_lifecycle_locks.lock(&id).await;
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if instance.status != "running" {
        return Err(ApiError::bad_request("instance is not running"));
    }
    if instance.pcap_status == "capturing" {
        return Ok(Json(ApiEnvelope {
            success: true,
            data: instance,
        }));
    }
    let workload_id = instance
        .workload_id
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("instance workload is missing"))?;
    let capture = match state.agent.start_pcap(workload_id).await {
        Ok(capture) => capture,
        Err(error) => {
            emit_operation_event(
                &state,
                operation_event_builder(
                    "capture_started",
                    "开始抓包",
                    "Start capture",
                    "simulation_instance",
                    &id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    operation_context.as_deref(),
                )
                .error("CAPTURE_START_FAILED", "Capture start failed")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
            return Err(error.into());
        }
    };
    let started_at = chrono::Utc::now().timestamp();
    let updated = db::update_pcap_state(
        &state.db,
        &id,
        "capturing",
        Some(started_at),
        Some(&capture.capture_id),
        None,
    )
    .await?
    .unwrap_or(instance);
    schedule_pcap_auto_stop(state.clone(), id.clone(), capture.capture_id, started_at);
    emit_operation_event(
        &state,
        operation_event(
            "capture_started",
            "开始抓包",
            "Start capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

/// 停止指定实例的抓包，将有效 PCAP 持久化后更新实例状态。
async fn stop_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if instance.pcap_status != "capturing" {
        return Ok(Json(ApiEnvelope {
            success: true,
            data: instance,
        }));
    }
    let updated = match finalize_pcap_capture(&state, &id, None).await {
        Ok(Some((updated, _))) => updated,
        Ok(None) => return Err(ApiError::not_found("instance not found")),
        Err(error) => {
            emit_operation_event(
                &state,
                operation_event_builder(
                    "capture_stopped",
                    "停止抓包",
                    "Stop capture",
                    "simulation_instance",
                    &id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    operation_context.as_deref(),
                )
                .error("CAPTURE_STOP_FAILED", "Capture stop failed")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
            return Err(error.into());
        }
    };
    emit_operation_event(
        &state,
        operation_event(
            "capture_stopped",
            "停止抓包",
            "Stop capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

/// 按抓包开始时间安排最长持续时间到期任务。
fn schedule_pcap_auto_stop(
    state: Arc<AppState>,
    instance_id: String,
    capture_id: String,
    started_at: i64,
) {
    tokio::spawn(async move {
        let deadline = started_at.saturating_add(PCAP_MAX_DURATION_SECS);
        let delay = deadline.saturating_sub(chrono::Utc::now().timestamp()) as u64;
        tokio::time::sleep(Duration::from_secs(delay)).await;
        auto_stop_pcap(&state, &instance_id, &capture_id).await;
    });
}

/// 扫描并尝试结束服务重启期间遗留的过期抓包。
async fn finalize_expired_pcap_captures(state: &AppState) {
    let Ok(instances) = db::list_instances(&state.db).await else {
        return;
    };
    let deadline = chrono::Utc::now().timestamp() - PCAP_MAX_DURATION_SECS;
    for instance in instances {
        if instance.pcap_status == "capturing"
            && instance
                .pcap_start_time
                .is_some_and(|started| started <= deadline)
            && let Some(capture_id) = instance.pcap_capture_id.as_deref()
        {
            auto_stop_pcap(state, &instance.id, capture_id).await;
        }
    }
}

/// 在持续时间上限到达时结束匹配的抓包，并记录后台操作结果。
async fn auto_stop_pcap(state: &AppState, instance_id: &str, capture_id: &str) {
    match finalize_pcap_capture(state, instance_id, Some(capture_id)).await {
        Ok(Some((_, true))) => {
            emit_operation_event(
                state,
                operation_event(
                    "capture_stopped",
                    "停止抓包",
                    "Stop capture",
                    "simulation_instance",
                    instance_id,
                    (OperationOutcome::Success, OperationImpact::Info),
                    None,
                ),
            )
            .await;
        }
        Ok(Some((_, false)) | None) => {}
        Err(error) => {
            tracing::error!(
                instance_id,
                capture_id,
                %error,
                "failed to stop pcap capture at duration limit"
            );
            emit_operation_event(
                state,
                operation_event_builder(
                    "capture_stopped",
                    "停止抓包",
                    "Stop capture",
                    "simulation_instance",
                    instance_id,
                    (OperationOutcome::Failure, OperationImpact::Error),
                    None,
                )
                .error("CAPTURE_AUTO_STOP_FAILED", "Capture auto stop failed")
                .build()
                .expect("static operation event must be valid"),
            )
            .await;
        }
    }
}

/// 在实例生命周期锁内结束抓包并完成 PCAP 状态转换。
///
/// `expected_capture_id` 用于拒绝已过期的自动停止任务；返回值中的布尔值表示本次是否
/// 实际结束了抓包。只含 PCAP 头的空结果转为 `idle`，其他结果写入数据目录并转为 `ready`。
async fn finalize_pcap_capture(
    state: &AppState,
    instance_id: &str,
    expected_capture_id: Option<&str>,
) -> anyhow::Result<Option<(Instance, bool)>> {
    let _guard = state.instance_lifecycle_locks.lock(instance_id).await;
    let Some(instance) = db::get_instance(&state.db, instance_id).await? else {
        return Ok(None);
    };
    if instance.pcap_status != "capturing"
        || expected_capture_id
            .is_some_and(|expected| instance.pcap_capture_id.as_deref() != Some(expected))
    {
        return Ok(Some((instance, false)));
    }
    let workload_id = instance
        .workload_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("instance workload is missing"))?;
    let capture_id = instance
        .pcap_capture_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("pcap capture id is missing"))?;
    let pcap_bytes = state.agent.stop_pcap(workload_id, capture_id).await?;
    if pcap_bytes.len() <= 24 {
        return Ok(Some((
            db::update_pcap_state(&state.db, instance_id, "idle", None, None, None)
                .await?
                .unwrap_or(instance),
            true,
        )));
    }

    let pcap_dir = state.config.data_dir.join("pcap");
    tokio::fs::create_dir_all(&pcap_dir).await?;
    let file_name = pcap::capture_file_name(instance_id);
    tokio::fs::write(pcap_dir.join(&file_name), pcap_bytes).await?;
    Ok(Some((
        db::update_pcap_state(
            &state.db,
            instance_id,
            "ready",
            None,
            None,
            Some(&file_name),
        )
        .await?
        .unwrap_or(instance),
        true,
    )))
}

/// 删除指定实例的活动抓包、持久化文件和 PCAP 状态。
async fn delete_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let operation_context = operation_context(&headers);
    let _guard = state.instance_lifecycle_locks.lock(&id).await;
    let Some(instance) = db::get_instance(&state.db, &id).await? else {
        return Err(ApiError::not_found("instance not found"));
    };
    if instance.pcap_status == "capturing"
        && let (Some(workload_id), Some(capture_id)) = (
            instance.workload_id.as_deref(),
            instance.pcap_capture_id.as_deref(),
        )
        && let Err(error) = state.agent.stop_pcap(workload_id, capture_id).await
    {
        emit_operation_event(
            &state,
            operation_event_builder(
                "capture_deleted",
                "删除抓包",
                "Delete capture",
                "simulation_instance",
                &id,
                (OperationOutcome::Failure, OperationImpact::Error),
                operation_context.as_deref(),
            )
            .error("CAPTURE_DELETE_FAILED", "Capture deletion failed")
            .build()
            .expect("static operation event must be valid"),
        )
        .await;
        return Err(error.into());
    }
    if let Err(error) =
        pcap::remove_capture_file(&state.config.data_dir, instance.pcap_file_path.as_deref()).await
    {
        emit_operation_event(
            &state,
            operation_event_builder(
                "capture_deleted",
                "删除抓包",
                "Delete capture",
                "simulation_instance",
                &id,
                (OperationOutcome::Failure, OperationImpact::Error),
                operation_context.as_deref(),
            )
            .error("CAPTURE_FILE_DELETE_FAILED", "Capture file deletion failed")
            .build()
            .expect("static operation event must be valid"),
        )
        .await;
        return Err(error.into());
    }
    let updated = db::update_pcap_state(&state.db, &id, "idle", None, None, None)
        .await?
        .unwrap_or(instance);
    emit_operation_event(
        &state,
        operation_event(
            "capture_deleted",
            "删除抓包",
            "Delete capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Warning),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok(Json(ApiEnvelope {
        success: true,
        data: updated,
    }))
}

/// 下载指定实例已就绪的 PCAP 文件，并对成功或失败结果记录操作审计。
async fn download_pcap(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let operation_context = operation_context(&headers);
    let instance = match db::get_instance(&state.db, &id).await {
        Ok(Some(instance)) => instance,
        Ok(None) => {
            emit_capture_download_failure(
                &state,
                &id,
                operation_context.as_deref(),
                "INSTANCE_NOT_FOUND",
                "Simulation instance not found",
            )
            .await;
            return Err(ApiError::not_found("instance not found"));
        }
        Err(error) => {
            emit_capture_download_failure(
                &state,
                &id,
                operation_context.as_deref(),
                "INSTANCE_READ_FAILED",
                "Simulation instance lookup failed",
            )
            .await;
            return Err(error.into());
        }
    };
    let Some(file) = instance.pcap_file_path.as_deref() else {
        emit_capture_download_failure(
            &state,
            &id,
            operation_context.as_deref(),
            "CAPTURE_NOT_READY",
            "Capture is not ready for download",
        )
        .await;
        return Err(ApiError::not_found("pcap file not found"));
    };
    let bytes = match tokio::fs::read(state.config.data_dir.join("pcap").join(file)).await {
        Ok(bytes) => bytes,
        Err(_) => {
            emit_capture_download_failure(
                &state,
                &id,
                operation_context.as_deref(),
                "CAPTURE_READ_FAILED",
                "Capture file could not be read",
            )
            .await;
            return Err(ApiError::not_found("pcap file not found"));
        }
    };
    emit_operation_event(
        &state,
        operation_event(
            "capture_downloaded",
            "下载抓包",
            "Download capture",
            "simulation_instance",
            &id,
            (OperationOutcome::Success, OperationImpact::Info),
            operation_context.as_deref(),
        ),
    )
    .await;
    Ok((
        [
            ("content-type", "application/vnd.tcpdump.pcap"),
            ("content-disposition", "attachment"),
        ],
        bytes,
    )
        .into_response())
}

/// 提交 PCAP 下载失败操作事件，统一携带实例目标和错误语义。
async fn emit_capture_download_failure(
    state: &AppState,
    instance_id: &str,
    operation_context_id: Option<&str>,
    error_code: &str,
    error_summary: &str,
) {
    let event = operation_event_builder(
        "capture_downloaded",
        "下载抓包",
        "Download capture",
        "simulation_instance",
        instance_id,
        (OperationOutcome::Failure, OperationImpact::Error),
        operation_context_id,
    )
    .error(error_code, error_summary)
    .build()
    .expect("static operation event must be valid");
    emit_operation_event(state, event).await;
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditLogQuery {
    #[serde(default = "default_audit_log_page")]
    page: u32,
    #[serde(default = "default_audit_log_page_size")]
    page_size: u32,
}

fn default_audit_log_page() -> u32 {
    1
}

fn default_audit_log_page_size() -> u32 {
    50
}

/// 校验分页参数并返回指定实例的审计日志页。
async fn list_instance_logs(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<AuditLogQuery>,
) -> ApiResult<impl IntoResponse> {
    if query.page == 0 {
        return Err(ApiError::bad_request("page must be greater than zero"));
    }
    if query.page_size == 0 || query.page_size > 200 {
        return Err(ApiError::bad_request("pageSize must be between 1 and 200"));
    }
    if db::get_instance(&state.db, &id).await?.is_none() {
        return Err(ApiError::not_found("simulation instance not found"));
    }
    let (total, records) =
        db::list_instance_logs(&state.db, &id, query.page, query.page_size).await?;
    Ok(Json(ApiEnvelope {
        success: true,
        data: AuditLogPage {
            total,
            page: query.page,
            page_size: query.page_size,
            records,
        },
    }))
}

/// 接收仿真引擎上报的运行时事件，校验回调令牌与端点归属后写入审计日志。
async fn record_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EventRequest>,
) -> ApiResult<impl IntoResponse> {
    validate_runtime_event(&payload)?;
    let Some(instance) = db::get_instance(&state.db, &payload.instance_id).await? else {
        return Err(ApiError::not_found("simulation instance not found"));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !presented.is_some_and(|token| {
        constant_time_eq::constant_time_eq(token.as_bytes(), instance.callback_token.as_bytes())
    }) {
        return Err(ApiError::unauthorized("invalid simulation callback token"));
    }
    if !instance
        .endpoints
        .iter()
        .any(|endpoint| endpoint.endpoint_id == payload.endpoint_id)
    {
        return Err(ApiError::bad_request(
            "event endpoint does not belong to instance",
        ));
    }
    let log = match state.audit_logs.write(payload).await {
        Ok(log) => log,
        Err(db::AuditLogWriteError::InstanceNotFound) => {
            return Err(ApiError::not_found("simulation instance not found"));
        }
        Err(db::AuditLogWriteError::Internal(error)) => return Err(error.into()),
    };
    Ok((
        StatusCode::CREATED,
        Json(ApiEnvelope {
            success: true,
            data: log,
        }),
    ))
}

/// 校验运行时事件的版本、标识符、时间戳以及元数据和载荷大小边界。
fn validate_runtime_event(event: &EventRequest) -> ApiResult<()> {
    if event.schema_version != 1 {
        return Err(ApiError::bad_request(
            "only simulation runtime event schemaVersion 1 is supported",
        ));
    }
    Uuid::parse_str(&event.event_id)
        .map_err(|_| ApiError::bad_request("eventId must be a UUID"))?;
    if event.event_type.is_empty()
        || event.event_type.len() > 64
        || !event
            .event_type
            .chars()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
    {
        return Err(ApiError::bad_request("eventType is invalid"));
    }
    if event.summary.is_empty() || event.summary.len() > 2_048 {
        return Err(ApiError::bad_request(
            "event summary must contain between 1 and 2048 bytes",
        ));
    }
    if !event.metadata.is_object()
        || serde_json::to_vec(&event.metadata).is_ok_and(|value| value.len() > 16 * 1024)
    {
        return Err(ApiError::bad_request(
            "event metadata is invalid or too large",
        ));
    }
    if let Some(payload) = event.payload_hex.as_deref()
        && (payload.len() > 8 * 1024
            || !payload.len().is_multiple_of(2)
            || !payload.chars().all(|value| value.is_ascii_hexdigit()))
    {
        return Err(ApiError::bad_request(
            "event payloadHex is invalid or too large",
        ));
    }
    if let Some(timestamp) = event.timestamp.as_deref() {
        chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|_| ApiError::bad_request("event timestamp must be RFC 3339"))?;
    }
    Ok(())
}

fn parse_protocol(protocol: &str) -> ApiResult<ProtocolId> {
    ProtocolId::from_str(protocol).map_err(ApiError::bad_request)
}

/// 使用静态语义字段构建完整操作审计事件。
fn operation_event(
    code: &str,
    zh_cn: &str,
    en_us: &str,
    target_kind: &str,
    target_id: &str,
    result: (OperationOutcome, OperationImpact),
    operation_context_id: Option<&str>,
) -> OperationEvent {
    operation_event_builder(
        code,
        zh_cn,
        en_us,
        target_kind,
        target_id,
        result,
        operation_context_id,
    )
    .build()
    .expect("static operation event must be valid")
}

/// 构建带可信操作上下文和显式资源目标的审计事件生成器。
fn operation_event_builder(
    code: &str,
    zh_cn: &str,
    en_us: &str,
    target_kind: &str,
    target_id: &str,
    result: (OperationOutcome, OperationImpact),
    operation_context_id: Option<&str>,
) -> veydeck_suite_runtime::OperationEventBuilder {
    let builder =
        OperationEvent::builder(code, zh_cn, en_us, result.0, result.1).target(OperationTarget {
            kind: target_kind.to_string(),
            id: target_id.to_string(),
            display_name: None,
            ownership: None,
        });
    match operation_context_id {
        Some(value) => builder.operation_context_id(value),
        None => builder,
    }
}

/// 从代理注入的请求头中提取并规范化可信操作上下文标识符。
fn operation_context(headers: &HeaderMap) -> Option<String> {
    veydeck_suite_runtime::operation_context_from_header(
        headers
            .get(veydeck_suite_runtime::OPERATION_CONTEXT_HEADER)
            .and_then(|value| value.to_str().ok()),
    )
}

/// 向 Agent 提交操作审计事件；提交失败只记录服务端错误，不改写业务结果。
async fn emit_operation_event(state: &AppState, event: OperationEvent) {
    if let Err(error) = state.agent.submit_operation_event(&event).await {
        tracing::error!(event_id = %event.event_id, %error, "operation audit event was not accepted");
    }
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
            message_key: None,
            cause: None,
        }
    }

    fn with_message_key(mut self, message_key: impl Into<String>) -> Self {
        self.message_key = Some(message_key.into());
        self
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        let message = value.to_string();
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
            message_key: None,
            cause: Some(value),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(
                status = %self.status,
                message = %self.message,
                error = %error_detail(self.cause.as_ref(), &self.message),
                "HTTP request handling failed"
            );
        }
        (
            self.status,
            Json(ErrorEnvelope {
                success: false,
                message: self.message,
                message_key: self.message_key,
            }),
        )
            .into_response()
    }
}

/// 生成用于服务端日志的完整错误链，同时为无底层错误的 500 保留可诊断消息。
fn error_detail(cause: Option<&anyhow::Error>, message: &str) -> String {
    cause
        .map(|error| format!("{error:#}"))
        .unwrap_or_else(|| message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_workload_name_uses_host_port_rule_number_and_instance_suffix() {
        assert_eq!(
            simulation_workload_name(
                "sim-rule-190001",
                8080,
                "sim-019f409d-8e1d-73e0-f3dc45e75209"
            ),
            "8080-190001-e75209"
        );
    }

    #[test]
    fn simulation_workload_name_keeps_local_rule_identifier() {
        assert_eq!(
            simulation_workload_name(
                "rule-019ff3b6-bb91-7f40-bee8-fb4689a0e599",
                2222,
                "sim-019f409d-8e1d-73e0-f3dc45abcdef"
            ),
            "2222-019ff3b6-bb91-7f40-bee8-fb4689a0e599-abcdef"
        );
    }

    #[test]
    fn internal_error_detail_contains_complete_error_chain() {
        let error = anyhow::anyhow!("database is locked").context("failed to list rules");
        let detail = error_detail(Some(&error), "fallback");

        assert!(detail.contains("failed to list rules"));
        assert!(detail.contains("database is locked"));
    }

    #[tokio::test]
    async fn internal_error_response_keeps_existing_envelope() {
        let response = ApiError::from(anyhow::anyhow!("database unavailable")).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "success": false,
                "message": "database unavailable"
            })
        );
    }

    #[tokio::test]
    async fn expired_capture_task_ignores_an_already_deleted_instance() {
        let data_dir = tempfile::tempdir().unwrap();
        let state = AppState::initialize(crate::Config {
            http_port: 8080,
            data_dir: data_dir.path().to_path_buf(),
            frontend_dir: data_dir.path().to_path_buf(),
            agent_runtime_path: data_dir.path().join("runtime.json"),
            suite_id: "veydeck.protocol-simulation".to_string(),
            suite_instance_id: "suite-instance-1".to_string(),
            engine_image: "protocol-simulation-engine:test".to_string(),
            event_callback_url: protocol_simulation_common::DEFAULT_EVENT_CALLBACK_URL.to_string(),
            audit_max_per_instance: 10_000,
        })
        .await
        .unwrap();

        let result = finalize_pcap_capture(&state, "missing-instance", Some("capture-1"))
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn operation_event_contains_only_trusted_semantic_fields() {
        let event = operation_event(
            "instance_deployed",
            "部署仿真实例",
            "Deploy simulation instance",
            "simulation_instance",
            "sim-1",
            (OperationOutcome::Success, OperationImpact::Info),
            Some("context-1"),
        );
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["eventCode"], "instance_deployed");
        assert_eq!(value["operationContextId"], "context-1");
        assert_eq!(value["target"]["id"], "sim-1");
        assert!(value.get("actor").is_none());
        assert!(value.get("module").is_none());
    }

    #[test]
    fn capture_download_event_targets_instance_without_task_id_or_file_path() {
        let event = operation_event(
            "capture_downloaded",
            "下载抓包",
            "Download capture",
            "simulation_instance",
            "sim-1",
            (OperationOutcome::Success, OperationImpact::Info),
            Some("context-1"),
        );
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["eventCode"], "capture_downloaded");
        assert_eq!(value["target"]["id"], "sim-1");
        assert!(value["taskId"].is_null());
        assert!(
            value["parameters"]
                .as_object()
                .is_some_and(|value| value.is_empty())
        );
    }

    #[test]
    fn runtime_event_validation_rejects_oversized_or_non_hex_payloads() {
        let mut event = EventRequest {
            schema_version: 1,
            event_id: Uuid::now_v7().to_string(),
            instance_id: "instance-1".to_string(),
            endpoint_id: "main".to_string(),
            event_type: "connection".to_string(),
            summary: "client connected".to_string(),
            client_ip: "192.0.2.1".to_string(),
            client_port: 12345,
            payload_hex: Some("00ff".to_string()),
            metadata: serde_json::json!({"protocol": "http"}),
            timestamp: Some("2026-08-11T00:00:00Z".to_string()),
        };
        assert!(validate_runtime_event(&event).is_ok());
        event.payload_hex = Some("not-hex".to_string());
        assert!(validate_runtime_event(&event).is_err());
    }
}
