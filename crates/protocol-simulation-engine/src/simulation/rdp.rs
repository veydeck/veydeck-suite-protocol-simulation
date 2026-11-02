//! RDP 协议仿真运行器。
//!
//! 初版实现 X.224 Connection Request/Confirm 层级的仿真：
//! 解析客户端 Connection Request PDU 中的 cookie（用户名提示）和
//! 请求协议类型，返回合法的 Connection Confirm PDU，并记录审计日志。
//! 不实现完整的 MCS/Security Exchange/认证流程。

use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimRdpConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::{error, info};

/// RDP 仿真运行器共享上下文。
struct RdpSimulationContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
}

// --- X.224 / TPKT 协议常量 ---

/// TPKT 版本号。
const TPKT_VERSION: u8 = 3;
/// X.224 Connection Confirm PDU 类型码。
const X224_CC_PDU_TYPE: u8 = 0xD0;
/// RDP 协商响应类型标识。
const RDP_NEG_RSP_TYPE: u8 = 0x02;
/// RDP 协商响应长度。
const RDP_NEG_RSP_LENGTH: u16 = 8;

/// 从 X.224 Connection Request 中提取 cookie 和请求协议信息。
///
/// Connection Request PDU 格式（RFC 2126 / MS-RDPBCGR）：
/// - TPKT header (4 bytes): version(1) + reserved(1) + length(2)
/// - X.224 CR header: length(1) + CR code(1) + dst_ref(2) + src_ref(2) + class(1)
/// - 可选 cookie 或 RDP Negotiation Request
fn parse_connection_request(data: &[u8]) -> (Option<String>, Option<u32>) {
    // 最小长度检查：TPKT(4) + X.224 CR header(7) = 11 字节
    if data.len() < 11 {
        return (None, None);
    }

    // 验证 TPKT 版本
    if data[0] != TPKT_VERSION {
        return (None, None);
    }

    // X.224 CR PDU 类型码应为 0xE0
    if data[5] != 0xE0 {
        return (None, None);
    }

    let payload = &data[11..];
    let cookie_end = payload.windows(2).position(|v| v == b"\r\n").map(|p| p + 2);
    let cookie = cookie_end
        .and_then(|end| std::str::from_utf8(&payload[..end]).ok())
        .and_then(|line| line.strip_prefix("Cookie: mstshash="))
        .map(|value| value.trim().to_string());
    let negotiation = if cookie.is_some() {
        &payload[cookie_end.unwrap()..]
    } else {
        payload
    };
    let requested_protocols =
        if negotiation.len() == 8 && negotiation[0] == 1 && negotiation[2..4] == [8, 0] {
            Some(u32::from_le_bytes(negotiation[4..8].try_into().unwrap()))
        } else {
            None
        };

    (cookie, requested_protocols)
}

/// 构建 X.224 Connection Confirm PDU 响应。
///
/// 响应结构：
/// - TPKT header (4 bytes)
/// - X.224 CC header (7 bytes)
/// - RDP Negotiation Response (8 bytes)
fn build_connection_confirm(selected_protocol: u32) -> Vec<u8> {
    let total_length: u16 = 4 + 7 + 8; // TPKT + X.224 CC + RDP Neg Response
    let x224_length: u8 = 6 + 8; // X.224 CC 负载长度

    let mut response = Vec::with_capacity(total_length as usize);

    // TPKT header
    response.push(TPKT_VERSION);
    response.push(0); // reserved
    response.extend_from_slice(&total_length.to_be_bytes());

    // X.224 CC header
    response.push(x224_length);
    response.push(X224_CC_PDU_TYPE);
    response.extend_from_slice(&[0x00, 0x00]); // dst_ref
    response.extend_from_slice(&[0x00, 0x00]); // src_ref
    response.push(0x00); // class

    // RDP Negotiation Response
    response.push(RDP_NEG_RSP_TYPE);
    response.push(0x00); // flags
    response.extend_from_slice(&RDP_NEG_RSP_LENGTH.to_le_bytes());
    response.extend_from_slice(&selected_protocol.to_le_bytes());

    response
}

fn negotiation_response(requested: Option<u32>) -> Vec<u8> {
    match requested {
        Some(0) => build_connection_confirm(0),
        Some(_) => {
            // SSL_NOT_ALLOWED_BY_SERVER: do not select an unrequested TLS/NLA mode.
            let mut response = build_connection_confirm(2);
            response[11] = 3;
            response
        }
        None => vec![3, 0, 0, 11, 6, 0xd0, 0, 0, 0, 0, 0],
    }
}

/// 将请求协议位掩码转换为可读的协议名称。
fn protocol_flags_to_string(flags: u32) -> String {
    let mut protocols = Vec::new();
    if flags == 0 {
        protocols.push("Standard RDP Security");
    }
    if flags & 0x01 != 0 {
        protocols.push("TLS");
    }
    if flags & 0x02 != 0 {
        protocols.push("CredSSP (NLA)");
    }
    if flags & 0x08 != 0 {
        protocols.push("RDSTLS");
    }
    if protocols.is_empty() {
        return format!("Unknown (0x{:08X})", flags);
    }
    protocols.join(" + ")
}

/// 处理单个 RDP 仿真 TCP 连接。
async fn handle_rdp_connection(
    ctx: Arc<RdpSimulationContext>,
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
            detail_summary: "RDP client connected".to_string(),
            payload_hex: None,
        },
    );

    // A TCP read is not a TPKT message: read and validate the declared frame.
    let request = tokio::time::timeout(super::wire::IDLE_TIMEOUT, async {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        anyhow::ensure!(header[..2] == [3, 0], "invalid TPKT header");
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        anyhow::ensure!((11..=4096).contains(&length), "invalid TPKT length");
        let mut packet = header.to_vec();
        packet.resize(length, 0);
        stream.read_exact(&mut packet[4..]).await?;
        anyhow::ensure!(
            packet[5] == 0xe0 && usize::from(packet[4]) + 5 == length,
            "invalid X.224 request"
        );
        Ok::<_, anyhow::Error>(packet)
    })
    .await??;
    let request_data = &request;
    let mut buffer = vec![0; 4096];
    let (cookie, requested_protocols) = parse_connection_request(request_data);

    // 构建审计日志摘要
    let username_hint = cookie.as_deref().unwrap_or("(none)");
    let protocol_str = requested_protocols
        .map(protocol_flags_to_string)
        .unwrap_or_else(|| "(not specified)".to_string());

    let summary = format!(
        "RDP Connection Request: user_hint={}, protocols={}",
        username_hint, protocol_str
    );

    // 上报 X.224 协商事件
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: client_ip.clone(),
            client_port,
            server_port: ctx.port,
            event_type: "rdp_negotiation".to_string(),
            detail_summary: summary,
            payload_hex: Some(super::common::encode_hex(
                &request_data[..request_data.len().min(512)],
            )),
        },
    );

    // 发送 X.224 Connection Confirm 响应
    // 选择 Standard RDP Security (0x00) 以避免 TLS/NLA 协商失败
    let confirm = negotiation_response(requested_protocols);
    stream.write_all(&confirm).await?;
    // Discovery ends at negotiation; no MCS or security session is advertised.
    if requested_protocols.is_some_and(|flags| flags != 0) {
        return Ok(());
    }

    // 继续读取后续数据（MCS Connect Initial 等），仅记录不做深层解析
    loop {
        let read_len = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };

        let payload = &buffer[..read_len];
        report_sim_log_async(
            ctx.callback_url.clone(),
            SimLogDraft {
                rule_id: ctx.rule_id.clone(),
                node_id: ctx.node_id.clone(),
                client_ip: client_ip.clone(),
                client_port,
                server_port: ctx.port,
                event_type: "exploit_attempt".to_string(),
                detail_summary: format!("RDP data received ({} bytes)", read_len),
                payload_hex: Some(super::common::encode_hex(
                    &payload[..payload.len().min(512)],
                )),
            },
        );
    }

    Ok(())
}

/// 开启 RDP TCP 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_rdp_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    _config: SimRdpConfig,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(RdpSimulationContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
    });

    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation RDP server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_rdp_connection(conn_ctx, stream, peer).await {
                        error!("RDP simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!(
                    "Simulation RDP server for rule '{}' (ID: {}) on port {} gracefully shutting down...",
                    name_str, rule_id, port
                );
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_does_not_claim_tls_or_nla() {
        assert_eq!(negotiation_response(None).len(), 11);
        let standard = negotiation_response(Some(0));
        assert_eq!(standard[11], 2);
        assert_eq!(&standard[15..19], &[0; 4]);
        let tls = negotiation_response(Some(3));
        assert_eq!(tls[11], 3);
        assert_eq!(&tls[15..19], &2_u32.to_le_bytes());
    }
    #[test]
    fn cookie_and_binary_negotiation_are_parsed_separately() {
        let mut data = vec![3, 0, 0, 0, 0, 0xe0, 0, 0, 0, 0, 0];
        data.extend_from_slice(b"Cookie: mstshash=user\r\n");
        data.extend_from_slice(&[1, 0, 8, 0, 3, 0, 0, 0]);
        assert_eq!(
            parse_connection_request(&data),
            (Some("user".into()), Some(3))
        );
    }
}
