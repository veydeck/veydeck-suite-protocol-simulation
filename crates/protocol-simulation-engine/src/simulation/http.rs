//! HTTP 协议仿真运行器。

use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimHttpConfig;
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::info;

/// 全局共享的 HTTP 仿真参数，由 Axum 路由 Handler 消费。
struct SimulationContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimHttpConfig,
}

/// 默认高保真的系统登录端伪造 HTML。
const DEFAULT_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Embedded Web Management Console</title>
    <style>
        body { background: #121214; color: #e2e2e8; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-box { background: #1a1a1e; padding: 40px; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.5); width: 320px; border: 1px solid #2e2e34; }
        h2 { margin: 0 0 24px; font-size: 20px; font-weight: 500; text-align: center; color: #3b82f6; }
        .input-group { margin-bottom: 16px; }
        label { display: block; margin-bottom: 6px; font-size: 12px; color: #a1a1aa; }
        input { width: 100%; padding: 10px; border: 1px solid #3f3f46; background: #27272a; border-radius: 4px; color: #fff; box-sizing: border-box; }
        button { width: 100%; padding: 12px; border: none; background: #3b82f6; color: #fff; font-size: 14px; font-weight: 500; border-radius: 4px; cursor: pointer; margin-top: 8px; }
        button:hover { background: #2563eb; }
        .footer { margin-top: 24px; text-align: center; font-size: 11px; color: #71717a; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Web Management Login</h2>
        <form onsubmit="event.preventDefault(); alert('Authentication timeout. Please try again.');">
            <div class="input-group">
                <label>USERNAME</label>
                <input type="text" autocomplete="off" placeholder="admin" required />
            </div>
            <div class="input-group">
                <label>PASSWORD</label>
                <input type="password" required />
            </div>
            <button type="submit">Log In</button>
        </form>
        <div class="footer">Firmware v4.8.1-release. All rights reserved.</div>
    </div>
</body>
</html>"#;

/// 核心路由拦截 Handler。
async fn simulation_handler(
    State(ctx): State<Arc<SimulationContext>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> impl IntoResponse {
    let method = req.method().as_str().to_uppercase();
    let path = req.uri().path().to_string();
    let client_ip = addr.ip().to_string();
    let client_port = addr.port();

    // 1. 尝试匹配配置的漏洞路径规则
    if let Some(exploit_paths) = &ctx.config.exploit_paths {
        for exp in exploit_paths {
            let path_matches = exp.path == path;
            let method_matches = exp
                .trigger_method
                .as_ref()
                .map(|m| m.to_uppercase() == method)
                .unwrap_or(true); // 若没有配置 method，则匹配所有请求

            if path_matches && method_matches {
                info!(
                    "Simulation hit exploit path: [{} {}] from {}:{} (Node: {})",
                    method, path, client_ip, client_port, ctx.node_id
                );

                // 1. 上报攻击审计日志
                let summary = format!(
                    "Exploit attempt triggered: {} {} - Returned custom status {}",
                    method, path, exp.response_status
                );
                let draft = SimLogDraft {
                    rule_id: ctx.rule_id.clone(),
                    node_id: ctx.node_id.clone(),
                    client_ip: client_ip.clone(),
                    client_port,
                    server_port: ctx.port,
                    event_type: "exploit_attempt".to_string(),
                    detail_summary: summary,
                    payload_hex: None,
                };
                report_sim_log_async(ctx.callback_url.clone(), draft);

                // 2. 组装漏洞响应
                let status = StatusCode::from_u16(exp.response_status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let mut response = Response::builder()
                    .status(status)
                    .body(Body::from(exp.response_body.clone()))
                    .unwrap();

                // 注入自定义 Header
                if let Some(headers) = &exp.response_headers {
                    for (k, v) in headers {
                        if let (Ok(name), Ok(val)) = (
                            HeaderName::from_bytes(k.as_bytes()),
                            HeaderValue::from_str(v),
                        ) {
                            response.headers_mut().insert(name, val);
                        }
                    }
                }

                // 强制覆写 Server Banner 标头
                if let Some(server) = &ctx.config.server_header {
                    let parsed = HeaderValue::from_str(server);
                    if let Ok(val) = parsed {
                        response
                            .headers_mut()
                            .insert(axum::http::header::SERVER, val);
                    }
                }

                return response;
            }
        }
    }

    // 2. 无漏洞路径匹配，返回普通 HTTP 仿真服务响应
    let summary = format!("Normal HTTP access: {} {}", method, path);
    let draft = SimLogDraft {
        rule_id: ctx.rule_id.clone(),
        node_id: ctx.node_id.clone(),
        client_ip: client_ip.clone(),
        client_port,
        server_port: ctx.port,
        event_type: "http_request".to_string(),
        detail_summary: summary,
        payload_hex: None,
    };
    report_sim_log_async(ctx.callback_url.clone(), draft);

    // 返回静态页面内容
    let body_content = ctx
        .config
        .html
        .clone()
        .unwrap_or_else(|| DEFAULT_HTML.to_string());
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(body_content))
        .unwrap();

    // 注入自定义 Header
    if let Some(headers) = &ctx.config.headers {
        for (k, v) in headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                response.headers_mut().insert(name, val);
            }
        }
    }

    // 强制覆写 Server Banner 标头
    if let Some(server) = &ctx.config.server_header {
        let parsed = HeaderValue::from_str(server);
        if let Ok(val) = parsed {
            response
                .headers_mut()
                .insert(axum::http::header::SERVER, val);
        }
    }

    response
}

/// 开启 HTTP 服务仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_http_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimHttpConfig,
    listener: tokio::net::TcpListener,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(SimulationContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });

    // 动态组装路由
    let app = Router::new()
        .fallback(any(simulation_handler))
        .with_state(ctx);

    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation HTTP server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );

    let name_str_shutdown = name_str.clone();
    let rule_id_shutdown = rule_id.clone();

    // 以优雅停机模式启动 Axum Serve 服务
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
        info!(
            "Simulation HTTP server for rule '{}' (ID: {}) on port {} gracefully shutting down...",
            name_str_shutdown, rule_id_shutdown, port
        );
    })
    .await?;

    Ok(())
}
