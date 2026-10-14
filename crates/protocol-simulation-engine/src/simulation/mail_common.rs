//! 邮件协议仿真运行器通用结构与行协议工具。

use super::common::{SimLogDraft, report_sim_log_async};
pub use super::config::{MailCredential, MailCustomResponse, MailMessage};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// 按 CRLF 行协议读取一行输入。
pub(super) async fn read_line(
    reader: &mut BufReader<OwnedReadHalf>,
) -> anyhow::Result<Option<String>> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).await?;
    if bytes == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

/// 写入一行 CRLF 响应。
pub(super) async fn write_line(
    writer: &mut OwnedWriteHalf,
    line: impl AsRef<str>,
) -> anyhow::Result<()> {
    writer.write_all(line.as_ref().as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    Ok(())
}

/// 写入多行已带协议格式的响应。
pub(super) async fn write_raw(
    writer: &mut OwnedWriteHalf,
    value: impl AsRef<str>,
) -> anyhow::Result<()> {
    writer.write_all(value.as_ref().as_bytes()).await?;
    Ok(())
}

/// 校验明文用户名密码。
pub(super) fn credentials_match(
    credentials: &[MailCredential],
    username: &str,
    password: &str,
) -> bool {
    credentials
        .iter()
        .any(|item| item.username == username && item.password == password)
}

/// 解码 AUTH PLAIN 载荷。
pub(super) fn decode_auth_plain(value: &str) -> Option<(String, String)> {
    let decoded = STANDARD.decode(value.trim()).ok()?;
    let mut parts = decoded.split(|byte| *byte == 0);
    let _authzid = parts.next();
    let username = String::from_utf8(parts.next()?.to_vec()).ok()?;
    let password = String::from_utf8(parts.next()?.to_vec()).ok()?;
    Some((username, password))
}

/// 解码 AUTH LOGIN 单段用户名或密码。
pub(super) fn decode_base64_text(value: &str) -> Option<String> {
    String::from_utf8(STANDARD.decode(value.trim()).ok()?).ok()
}

/// 按命令和参数内容匹配自定义响应。
pub(super) fn custom_response(
    responses: Option<&[MailCustomResponse]>,
    command: &str,
    command_text: &str,
    default_event_type: &str,
) -> Option<(String, String)> {
    let lowered = command_text.to_ascii_lowercase();
    for response in responses? {
        if !response.command.eq_ignore_ascii_case(command) {
            continue;
        }
        let args_match = response
            .args_contains
            .as_ref()
            .map(|items| {
                items
                    .iter()
                    .all(|item| lowered.contains(&item.to_ascii_lowercase()))
            })
            .unwrap_or(true);
        if args_match {
            return Some((
                response.response.clone(),
                response
                    .event_type
                    .clone()
                    .unwrap_or_else(|| default_event_type.to_string()),
            ));
        }
    }
    None
}

/// 生成 RFC 822 风格邮件内容。
pub(super) fn rfc822_message(message: &MailMessage) -> String {
    let mut headers = vec![
        format!("From: {}", message.from),
        format!("To: {}", message.to.join(", ")),
        format!("Subject: {}", message.subject),
    ];
    if let Some(date) = &message.date {
        headers.push(format!("Date: {}", date));
    }
    headers.push("MIME-Version: 1.0".to_string());
    headers.push("Content-Type: text/plain; charset=utf-8".to_string());
    format!("{}\r\n\r\n{}\r\n", headers.join("\r\n"), message.body)
}

/// IMAP flags 响应格式。
pub(super) fn imap_flags(message: &MailMessage) -> String {
    let flags = message.flags.as_deref().unwrap_or(&[]);
    if flags.is_empty() {
        "()".to_string()
    } else {
        format!("({})", flags.join(" "))
    }
}

/// 上报邮件协议连接日志。
pub(super) fn report_mail_connection(
    callback_url: &str,
    rule_id: &str,
    node_id: &str,
    client_ip: &str,
    client_port: u16,
    server_port: u16,
    protocol: &str,
) {
    report_sim_log_async(
        callback_url.to_string(),
        SimLogDraft {
            rule_id: rule_id.to_string(),
            node_id: node_id.to_string(),
            client_ip: client_ip.to_string(),
            client_port,
            server_port,
            event_type: "connection".to_string(),
            detail_summary: format!("{} client connected", protocol),
            payload_hex: None,
        },
    );
}

/// 上报邮件协议命令日志。
#[allow(clippy::too_many_arguments)]
pub(super) fn report_mail_command(
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
