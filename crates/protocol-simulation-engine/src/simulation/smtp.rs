//! SMTP 协议仿真运行器。

use super::config::SimSmtpConfig;
use super::mail_common::{
    MailCredential, credentials_match, custom_response, decode_auth_plain, decode_base64_text,
    read_line, report_mail_command, report_mail_connection, write_line,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::oneshot;
use tracing::{error, info};

struct SmtpContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimSmtpConfig,
}

struct SmtpSession {
    authed: bool,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
}

impl SmtpSession {
    fn new(require_auth: bool) -> Self {
        Self {
            authed: !require_auth,
            mail_from: None,
            rcpt_to: Vec::new(),
        }
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }
}

fn smtp_command(line: &str) -> (&str, &str) {
    line.split_once(' ')
        .map(|(command, args)| (command, args.trim()))
        .unwrap_or((line, ""))
}

async fn write_capabilities(
    writer: &mut OwnedWriteHalf,
    hostname: &str,
    capabilities: &[String],
) -> anyhow::Result<()> {
    write_line(writer, format!("250-{}", hostname)).await?;
    for capability in capabilities {
        write_line(writer, format!("250-{}", capability)).await?;
    }
    write_line(writer, "250 AUTH PLAIN LOGIN").await
}

async fn handle_auth_login(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    credentials: &[MailCredential],
    first_arg: &str,
) -> anyhow::Result<bool> {
    let username = if first_arg.is_empty() {
        write_line(writer, "334 VXNlcm5hbWU6").await?;
        let Some(line) = read_line(reader).await? else {
            return Ok(false);
        };
        decode_base64_text(&line).unwrap_or_default()
    } else {
        decode_base64_text(first_arg).unwrap_or_default()
    };

    write_line(writer, "334 UGFzc3dvcmQ6").await?;
    let Some(password_line) = read_line(reader).await? else {
        return Ok(false);
    };
    let password = decode_base64_text(&password_line).unwrap_or_default();
    Ok(credentials_match(credentials, &username, &password))
}

#[allow(clippy::too_many_arguments)]
async fn handle_smtp_connection(
    ctx: Arc<SmtpContext>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let client_ip = peer.ip().to_string();
    let client_port = peer.port();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let hostname = ctx
        .config
        .hostname
        .clone()
        .unwrap_or_else(|| "mail.veydeck.local".to_string());
    let capabilities = ctx.config.capabilities.clone().unwrap_or_else(|| {
        vec![
            "PIPELINING".to_string(),
            "SIZE 52428800".to_string(),
            "8BITMIME".to_string(),
        ]
    });
    let require_auth = ctx.config.require_auth.unwrap_or(false);
    let credentials = ctx.config.credentials.as_deref().unwrap_or(&[]);
    let mut session = SmtpSession::new(require_auth);

    let banner = ctx
        .config
        .banner
        .clone()
        .unwrap_or_else(|| format!("{} ESMTP Veydeck Mail Gateway", hostname));
    write_line(&mut writer, format!("220 {}", banner)).await?;
    report_mail_connection(
        &ctx.callback_url,
        &ctx.rule_id,
        &ctx.node_id,
        &client_ip,
        client_port,
        ctx.port,
        "SMTP",
    );

    loop {
        let Some(line) = read_line(&mut reader).await? else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let (command, args) = smtp_command(&line);
        let upper = command.to_ascii_uppercase();
        let mut event_type = "smtp_command".to_string();

        if let Some((response, custom_event)) = custom_response(
            ctx.config.custom_responses.as_deref(),
            &upper,
            &line,
            "smtp_command",
        ) {
            event_type = custom_event;
            write_line(&mut writer, response).await?;
        } else {
            match upper.as_str() {
                "EHLO" | "HELO" => {
                    if upper == "EHLO" {
                        write_capabilities(&mut writer, &hostname, &capabilities).await?;
                    } else {
                        write_line(&mut writer, format!("250 {}", hostname)).await?;
                    }
                }
                "AUTH" => {
                    event_type = "auth_attempt".to_string();
                    let mut parts = args.split_whitespace();
                    let mechanism = parts.next().unwrap_or_default().to_ascii_uppercase();
                    let initial = parts.next().unwrap_or_default();
                    let ok = match mechanism.as_str() {
                        "PLAIN" => {
                            let auth_value = if initial.is_empty() {
                                write_line(&mut writer, "334 ").await?;
                                read_line(&mut reader).await?.unwrap_or_default()
                            } else {
                                initial.to_string()
                            };
                            decode_auth_plain(&auth_value)
                                .map(|(user, pass)| credentials_match(credentials, &user, &pass))
                                .unwrap_or(false)
                        }
                        "LOGIN" => {
                            handle_auth_login(&mut reader, &mut writer, credentials, initial)
                                .await?
                        }
                        _ => false,
                    };
                    session.authed = ok;
                    if ok {
                        write_line(&mut writer, "235 2.7.0 Authentication successful").await?;
                    } else {
                        write_line(&mut writer, "535 5.7.8 Authentication credentials invalid")
                            .await?;
                    }
                }
                "MAIL" => {
                    if require_auth && !session.authed {
                        write_line(&mut writer, "530 5.7.0 Authentication required").await?;
                    } else if args.to_ascii_uppercase().starts_with("FROM:") {
                        session.mail_from = Some(args.to_string());
                        write_line(&mut writer, "250 2.1.0 Sender OK").await?;
                    } else {
                        write_line(&mut writer, "501 5.5.4 Syntax: MAIL FROM:<address>").await?;
                    }
                }
                "RCPT" => {
                    let allowed = ctx.config.accepted_recipients.as_deref().unwrap_or(&[]);
                    let allowed_match = allowed.is_empty()
                        || allowed.iter().any(|item| {
                            args.to_ascii_lowercase()
                                .contains(&item.to_ascii_lowercase())
                        });
                    if session.mail_from.is_none() {
                        write_line(&mut writer, "503 5.5.1 Need MAIL before RCPT").await?;
                    } else if allowed_match {
                        session.rcpt_to.push(args.to_string());
                        write_line(&mut writer, "250 2.1.5 Recipient OK").await?;
                    } else {
                        event_type = "exploit_attempt".to_string();
                        write_line(&mut writer, "550 5.1.1 User unknown").await?;
                    }
                }
                "DATA" => {
                    if session.rcpt_to.is_empty() {
                        write_line(&mut writer, "503 5.5.1 Need RCPT before DATA").await?;
                    } else {
                        write_line(&mut writer, "354 End data with <CR><LF>.<CR><LF>").await?;
                        let mut bytes = 0usize;
                        while let Some(data_line) = read_line(&mut reader).await? {
                            if data_line == "." {
                                break;
                            }
                            bytes += data_line.len();
                        }
                        event_type = "exploit_attempt".to_string();
                        session.reset_transaction();
                        write_line(
                            &mut writer,
                            format!("250 2.0.0 Message accepted for delivery ({} bytes)", bytes),
                        )
                        .await?;
                    }
                }
                "RSET" => {
                    session.reset_transaction();
                    write_line(&mut writer, "250 2.0.0 Reset state").await?;
                }
                "VRFY" | "EXPN" => {
                    event_type = "exploit_attempt".to_string();
                    write_line(
                        &mut writer,
                        "252 2.5.2 Cannot VRFY user, but will accept message",
                    )
                    .await?;
                }
                "NOOP" => write_line(&mut writer, "250 2.0.0 OK").await?,
                "QUIT" => {
                    write_line(&mut writer, "221 2.0.0 Bye").await?;
                    report_mail_command(
                        &ctx.callback_url,
                        &ctx.rule_id,
                        &ctx.node_id,
                        &client_ip,
                        client_port,
                        ctx.port,
                        &event_type,
                        "SMTP command: QUIT".to_string(),
                        &line,
                    );
                    break;
                }
                _ => write_line(&mut writer, "500 5.5.2 Command unrecognized").await?,
            }
        }

        report_mail_command(
            &ctx.callback_url,
            &ctx.rule_id,
            &ctx.node_id,
            &client_ip,
            client_port,
            ctx.port,
            &event_type,
            format!("SMTP command: {}", line),
            &line,
        );
    }

    Ok(())
}

/// 开启 SMTP 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_smtp_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimSmtpConfig,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(SmtpContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });
    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation SMTP server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_smtp_connection(conn_ctx, stream, peer).await {
                        error!("SMTP simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!("Simulation SMTP server for rule '{}' (ID: {}) on port {} gracefully shutting down...", name_str, rule_id, port);
                break;
            }
        }
    }
    Ok(())
}
