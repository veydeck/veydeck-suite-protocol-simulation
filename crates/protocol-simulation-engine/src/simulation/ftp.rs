//! FTP 协议仿真运行器。
//!
//! 实现标准 FTP 命令行交互：USER/PASS 认证流程、常见 FTP 命令响应、
//! 弱口令检测与审计日志上报。

use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimFtpConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;
use tracing::{error, info};

/// FTP 仿真运行器共享上下文。
struct FtpSimulationContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimFtpConfig,
}

/// FTP 会话状态。
struct FtpSession {
    /// 当前输入的用户名（尚未完成认证）。
    pending_user: Option<String>,
    /// 是否已通过认证。
    authed: bool,
    /// 认证后的用户名。
    username: Option<String>,
}

impl FtpSession {
    fn new() -> Self {
        Self {
            pending_user: None,
            authed: false,
            username: None,
        }
    }
}

/// 默认 FTP banner。
const DEFAULT_FTP_BANNER: &str = "ProFTPD 1.3.5e Server ready.";

/// 按 CRLF 行协议读取一行输入。
async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> anyhow::Result<Option<String>> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).await?;
    if bytes == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// 写入一行 CRLF 响应。
async fn write_line(writer: &mut OwnedWriteHalf, line: impl AsRef<str>) -> anyhow::Result<()> {
    writer.write_all(line.as_ref().as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    Ok(())
}

/// 校验 FTP 凭据是否匹配。
fn credentials_match(config: &SimFtpConfig, username: &str, password: &str) -> bool {
    // 匿名登录检查
    if config.allow_anonymous.unwrap_or(false)
        && (username.eq_ignore_ascii_case("anonymous") || username.eq_ignore_ascii_case("ftp"))
    {
        return true;
    }

    // 凭据列表比对
    if let Some(credentials) = &config.credentials {
        return credentials
            .iter()
            .any(|c| c.username == username && c.password == password);
    }

    false
}

/// 上报 FTP 协议审计日志。
#[allow(clippy::too_many_arguments)]
fn report_ftp_log(
    callback_url: &str,
    rule_id: &str,
    node_id: &str,
    client_ip: &str,
    client_port: u16,
    server_port: u16,
    event_type: &str,
    summary: String,
    command_line: &str,
) {
    report_sim_log_async(
        callback_url.to_string(),
        SimLogDraft {
            rule_id: rule_id.to_string(),
            node_id: node_id.to_string(),
            client_ip: client_ip.to_string(),
            client_port,
            server_port,
            event_type: event_type.to_string(),
            detail_summary: summary,
            payload_hex: Some(super::common::encode_hex(command_line.as_bytes())),
        },
    );
}

/// 处理单个 FTP 仿真 TCP 连接。
async fn handle_ftp_connection(
    ctx: Arc<FtpSimulationContext>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let client_ip = peer.ip().to_string();
    let client_port = peer.port();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut session = FtpSession::new();

    // 发送 220 欢迎 banner
    let banner = ctx.config.banner.as_deref().unwrap_or(DEFAULT_FTP_BANNER);
    write_line(&mut writer, format!("220 {}", banner)).await?;

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
            detail_summary: "FTP client connected".to_string(),
            payload_hex: None,
        },
    );

    loop {
        let Some(line) = read_line(&mut reader).await? else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }

        // 解析 FTP 命令和参数
        let (command, args) = line
            .split_once(' ')
            .map(|(c, a)| (c.trim(), a.trim()))
            .unwrap_or((line.as_str(), ""));
        let upper = command.to_ascii_uppercase();
        let mut event_type = "ftp_command";

        match upper.as_str() {
            "USER" => {
                event_type = "auth_attempt";
                session.pending_user = Some(args.to_string());
                session.authed = false;
                write_line(&mut writer, format!("331 Password required for {}", args)).await?;
            }
            "PASS" => {
                event_type = "auth_attempt";
                let username = session.pending_user.take().unwrap_or_default();
                if credentials_match(&ctx.config, &username, args) {
                    session.authed = true;
                    session.username = Some(username.clone());
                    write_line(&mut writer, format!("230 User {} logged in", username)).await?;
                } else {
                    // 认证失败，记录为利用尝试
                    event_type = "exploit_attempt";
                    write_line(&mut writer, "530 Login incorrect.").await?;
                }
            }
            "SYST" => {
                let syst_name = ctx.config.server_name.as_deref().unwrap_or("UNIX");
                write_line(&mut writer, format!("215 {} Type: L8", syst_name)).await?;
            }
            "FEAT" => {
                write_line(&mut writer, "211-Features:").await?;
                write_line(&mut writer, " UTF8").await?;
                write_line(&mut writer, " PASV").await?;
                write_line(&mut writer, " SIZE").await?;
                write_line(&mut writer, " MDTM").await?;
                write_line(&mut writer, "211 End").await?;
            }
            "PWD" | "XPWD" => {
                if !session.authed {
                    write_line(&mut writer, "530 Please login with USER and PASS.").await?;
                } else {
                    write_line(&mut writer, "257 \"/\" is the current directory").await?;
                }
            }
            "CWD" | "XCWD" => {
                if !session.authed {
                    write_line(&mut writer, "530 Please login with USER and PASS.").await?;
                } else {
                    write_line(&mut writer, "250 Directory successfully changed.").await?;
                }
            }
            "LIST" | "NLST" | "MLSD" => {
                if !session.authed {
                    write_line(&mut writer, "530 Please login with USER and PASS.").await?;
                } else {
                    // 无数据连接，直接返回无法建立被动连接的错误
                    write_line(&mut writer, "425 Use PASV or PORT first.").await?;
                }
            }
            "PASV" | "EPSV" => {
                if !session.authed {
                    write_line(&mut writer, "530 Please login with USER and PASS.").await?;
                } else {
                    // 不实现真正的数据通道，返回假的被动模式响应
                    write_line(&mut writer, "227 Entering Passive Mode (127,0,0,1,0,0).").await?;
                }
            }
            "TYPE" => {
                write_line(&mut writer, "200 Type set to I.").await?;
            }
            "SIZE" => {
                if !session.authed {
                    write_line(&mut writer, "530 Please login with USER and PASS.").await?;
                } else {
                    write_line(
                        &mut writer,
                        format!("550 {}: No such file or directory.", args),
                    )
                    .await?;
                }
            }
            "RETR" | "STOR" | "DELE" | "MKD" | "RMD" => {
                if !session.authed {
                    write_line(&mut writer, "530 Please login with USER and PASS.").await?;
                } else {
                    event_type = "exploit_attempt";
                    write_line(&mut writer, "550 Permission denied.").await?;
                }
            }
            "NOOP" => {
                write_line(&mut writer, "200 NOOP ok.").await?;
            }
            "QUIT" => {
                write_line(&mut writer, "221 Goodbye.").await?;
                report_ftp_log(
                    &ctx.callback_url,
                    &ctx.rule_id,
                    &ctx.node_id,
                    &client_ip,
                    client_port,
                    ctx.port,
                    event_type,
                    "FTP command: QUIT".to_string(),
                    &line,
                );
                break;
            }
            _ => {
                write_line(
                    &mut writer,
                    format!("500 '{}': command not understood.", upper),
                )
                .await?;
            }
        }

        // 上报命令审计日志
        report_ftp_log(
            &ctx.callback_url,
            &ctx.rule_id,
            &ctx.node_id,
            &client_ip,
            client_port,
            ctx.port,
            event_type,
            format!("FTP command: {}", line),
            &line,
        );
    }

    Ok(())
}

/// 开启 FTP TCP 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_ftp_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimFtpConfig,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(FtpSimulationContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });

    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation FTP server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_ftp_connection(conn_ctx, stream, peer).await {
                        error!("FTP simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!(
                    "Simulation FTP server for rule '{}' (ID: {}) on port {} gracefully shutting down...",
                    name_str, rule_id, port
                );
                break;
            }
        }
    }

    Ok(())
}
