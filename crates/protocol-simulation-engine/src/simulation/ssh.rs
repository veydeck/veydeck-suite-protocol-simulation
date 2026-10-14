//! SSH 协议仿真运行器。
//!
//! 初版实现 banner 级别仿真：执行 SSH 传输层版本字符串交换，
//! 记录客户端 banner 和后续认证尝试原始载荷作为审计事件。
//! 不实现完整的密钥交换和加密通道。

use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimSshConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::{error, info};

/// SSH 仿真运行器共享上下文。
struct SshSimulationContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimSshConfig,
}

/// 默认 SSH 版本字符串。
const DEFAULT_SSH_BANNER: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";

/// 从原始字节流中尝试提取可打印的 ASCII 摘要，用于日志展示。
fn extract_printable_summary(data: &[u8], max_len: usize) -> String {
    let text: String = data
        .iter()
        .take(max_len)
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    text.trim_end_matches('.').to_string()
}

/// 处理单个 SSH 仿真 TCP 连接。
///
/// 流程：
/// 1. 发送服务端版本字符串
/// 2. 接收客户端版本字符串并记录
/// 3. 持续读取后续数据并记录为审计事件
async fn handle_ssh_connection(
    ctx: Arc<SshSimulationContext>,
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let client_ip = peer.ip().to_string();
    let client_port = peer.port();

    // 上报连接事件
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: client_ip.clone(),
            client_port,
            server_port: ctx.port,
            event_type: "connection".to_string(),
            detail_summary: "SSH client connected".to_string(),
            payload_hex: None,
        },
    );

    // 发送服务端版本字符串（SSH 协议要求以 \r\n 结尾）
    let server_banner = ctx.config.banner.as_deref().unwrap_or(DEFAULT_SSH_BANNER);
    let banner_line = format!("{}\r\n", server_banner);
    stream.write_all(banner_line.as_bytes()).await?;

    // 接收客户端版本字符串
    let mut buffer = vec![0u8; 4096];
    let read_len = stream.read(&mut buffer).await?;
    if read_len == 0 {
        return Ok(());
    }

    let client_data = &buffer[..read_len];
    let client_banner = String::from_utf8_lossy(client_data).trim().to_string();

    // 记录客户端版本字符串
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: client_ip.clone(),
            client_port,
            server_port: ctx.port,
            event_type: "auth_attempt".to_string(),
            detail_summary: format!("SSH client banner: {}", client_banner),
            payload_hex: Some(super::common::encode_hex(
                &client_data[..client_data.len().min(512)],
            )),
        },
    );

    // 持续读取后续认证尝试数据，直至连接断开或超时
    loop {
        let read_len = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            stream.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };

        let payload = &buffer[..read_len];
        let summary = format!(
            "SSH data received ({} bytes): {}",
            read_len,
            extract_printable_summary(payload, 128)
        );

        report_sim_log_async(
            ctx.callback_url.clone(),
            SimLogDraft {
                rule_id: ctx.rule_id.clone(),
                node_id: ctx.node_id.clone(),
                client_ip: client_ip.clone(),
                client_port,
                server_port: ctx.port,
                event_type: "exploit_attempt".to_string(),
                detail_summary: summary,
                payload_hex: Some(super::common::encode_hex(
                    &payload[..payload.len().min(512)],
                )),
            },
        );
    }

    Ok(())
}

/// 开启 SSH TCP 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_ssh_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimSshConfig,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(SshSimulationContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });

    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation SSH server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_ssh_connection(conn_ctx, stream, peer).await {
                        error!("SSH simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!(
                    "Simulation SSH server for rule '{}' (ID: {}) on port {} gracefully shutting down...",
                    name_str, rule_id, port
                );
                break;
            }
        }
    }

    Ok(())
}
