//! IMAP 协议仿真运行器。

use super::config::SimImapConfig;
use super::mail_common::{
    MailMessage, credentials_match, custom_response, decode_auth_plain, imap_flags, read_line,
    report_mail_command, report_mail_connection, rfc822_message, write_line, write_raw,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::sync::oneshot;
use tracing::{error, info};

struct ImapContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimImapConfig,
}

struct ImapSession {
    authed: bool,
    selected_mailbox: Option<String>,
}

fn default_mailbox_messages(config: &SimImapConfig) -> Vec<MailMessage> {
    config
        .mailboxes
        .as_ref()
        .and_then(|items| items.get("INBOX").cloned())
        .or_else(|| config.messages.clone())
        .unwrap_or_default()
}

fn imap_capabilities(config: &SimImapConfig) -> String {
    let caps = config.capabilities.clone().unwrap_or_else(|| {
        vec![
            "IMAP4rev1".to_string(),
            "UIDPLUS".to_string(),
            "AUTH=PLAIN".to_string(),
        ]
    });
    caps.join(" ")
}

fn parse_imap_line(line: &str) -> Option<(&str, String, String)> {
    let mut parts = line.splitn(3, ' ');
    let tag = parts.next()?;
    let command = parts.next()?.to_ascii_uppercase();
    let args = parts.next().unwrap_or_default().trim().to_string();
    Some((tag, command, args))
}

async fn require_imap_auth(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    tag: &str,
    session: &ImapSession,
) -> anyhow::Result<bool> {
    if session.authed {
        Ok(true)
    } else {
        write_line(writer, format!("{} NO Authentication required", tag)).await?;
        Ok(false)
    }
}

async fn write_fetch_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    tag: &str,
    sequence: usize,
    message: &MailMessage,
) -> anyhow::Result<()> {
    let body = rfc822_message(message);
    write_raw(
        writer,
        format!(
            "* {} FETCH (UID {} FLAGS {} RFC822.SIZE {} BODY[] {{{}}}\r\n{}",
            sequence,
            message.uid.as_deref().unwrap_or("1"),
            imap_flags(message),
            body.len(),
            body.len(),
            body
        ),
    )
    .await?;
    write_line(writer, ")").await?;
    write_line(writer, format!("{} OK FETCH completed", tag)).await
}

async fn handle_imap_connection(
    ctx: Arc<ImapContext>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let client_ip = peer.ip().to_string();
    let client_port = peer.port();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let credentials = ctx.config.credentials.as_deref().unwrap_or(&[]);
    let require_auth = ctx.config.require_auth.unwrap_or(false);
    let mut session = ImapSession {
        authed: !require_auth,
        selected_mailbox: None,
    };
    let messages = default_mailbox_messages(&ctx.config);

    let banner = ctx
        .config
        .banner
        .clone()
        .unwrap_or_else(|| "Veydeck IMAP service ready".to_string());
    write_line(&mut writer, format!("* OK {}", banner)).await?;
    report_mail_connection(
        &ctx.callback_url,
        &ctx.rule_id,
        &ctx.node_id,
        &client_ip,
        client_port,
        ctx.port,
        "IMAP",
    );

    loop {
        let Some(line) = read_line(&mut reader).await? else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let Some((tag, command, args)) = parse_imap_line(&line) else {
            write_line(&mut writer, "* BAD Invalid IMAP command").await?;
            continue;
        };
        let mut event_type = "imap_command".to_string();

        if let Some((response, custom_event)) = custom_response(
            ctx.config.custom_responses.as_deref(),
            &command,
            &line,
            "imap_command",
        ) {
            event_type = custom_event;
            write_line(&mut writer, response.replace("{tag}", tag)).await?;
        } else {
            match command.as_str() {
                "CAPABILITY" => {
                    write_line(
                        &mut writer,
                        format!("* CAPABILITY {}", imap_capabilities(&ctx.config)),
                    )
                    .await?;
                    write_line(&mut writer, format!("{} OK CAPABILITY completed", tag)).await?;
                }
                "NOOP" => write_line(&mut writer, format!("{} OK NOOP completed", tag)).await?,
                "LOGIN" => {
                    event_type = "auth_attempt".to_string();
                    let mut parts = args.split_whitespace();
                    let username = parts.next().unwrap_or_default().trim_matches('"');
                    let password = parts.next().unwrap_or_default().trim_matches('"');
                    session.authed = credentials_match(credentials, username, password);
                    if session.authed {
                        write_line(&mut writer, format!("{} OK LOGIN completed", tag)).await?;
                    } else {
                        write_line(&mut writer, format!("{} NO LOGIN failed", tag)).await?;
                    }
                }
                "AUTHENTICATE" => {
                    event_type = "auth_attempt".to_string();
                    if args.eq_ignore_ascii_case("PLAIN") {
                        write_line(&mut writer, "+").await?;
                        if let Some(auth_line) = read_line(&mut reader).await?
                            && let Some((username, password)) = decode_auth_plain(&auth_line)
                        {
                            session.authed = credentials_match(credentials, &username, &password);
                        }
                    }
                    if session.authed {
                        write_line(&mut writer, format!("{} OK AUTHENTICATE completed", tag))
                            .await?;
                    } else {
                        write_line(&mut writer, format!("{} NO AUTHENTICATE failed", tag)).await?;
                    }
                }
                "LIST" | "LSUB" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        write_line(&mut writer, r#"* LIST (\HasNoChildren) "/" "INBOX""#).await?;
                        if let Some(mailboxes) = &ctx.config.mailboxes {
                            for name in mailboxes.keys().filter(|name| name.as_str() != "INBOX") {
                                write_line(
                                    &mut writer,
                                    format!(r#"* LIST (\HasNoChildren) "/" "{}""#, name),
                                )
                                .await?;
                            }
                        }
                        write_line(&mut writer, format!("{} OK LIST completed", tag)).await?;
                    }
                }
                "STATUS" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        write_line(
                            &mut writer,
                            format!(
                                r#"* STATUS INBOX (MESSAGES {} UNSEEN {} UIDNEXT {})"#,
                                messages.len(),
                                messages.len(),
                                messages.len() + 1
                            ),
                        )
                        .await?;
                        write_line(&mut writer, format!("{} OK STATUS completed", tag)).await?;
                    }
                }
                "SELECT" | "EXAMINE" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        session.selected_mailbox = Some(args.trim_matches('"').to_string());
                        write_line(&mut writer, format!("* {} EXISTS", messages.len())).await?;
                        write_line(
                            &mut writer,
                            "* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)",
                        )
                        .await?;
                        write_line(&mut writer, format!("{} OK [{}] completed", tag, command))
                            .await?;
                    }
                }
                "SEARCH" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        let ids = (1..=messages.len())
                            .map(|value| value.to_string())
                            .collect::<Vec<_>>()
                            .join(" ");
                        write_line(&mut writer, format!("* SEARCH {}", ids)).await?;
                        write_line(&mut writer, format!("{} OK SEARCH completed", tag)).await?;
                    }
                }
                "FETCH" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        event_type = "exploit_attempt".to_string();
                        let index = args
                            .split_whitespace()
                            .next()
                            .and_then(|value| value.parse::<usize>().ok())
                            .unwrap_or(1)
                            .saturating_sub(1);
                        if let Some(message) = messages.get(index) {
                            write_fetch_response(&mut writer, tag, index + 1, message).await?;
                        } else {
                            write_line(&mut writer, format!("{} NO No such message", tag)).await?;
                        }
                    }
                }
                "UID" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        let mut uid_parts = args.splitn(3, ' ');
                        let subcommand = uid_parts.next().unwrap_or_default().to_ascii_uppercase();
                        if subcommand == "FETCH" {
                            event_type = "exploit_attempt".to_string();
                            let uid = uid_parts.next().unwrap_or("1");
                            let message = messages
                                .iter()
                                .find(|message| message.uid.as_deref() == Some(uid))
                                .or_else(|| messages.first());
                            if let Some(message) = message {
                                write_fetch_response(&mut writer, tag, 1, message).await?;
                            } else {
                                write_line(&mut writer, format!("{} NO No such message", tag))
                                    .await?;
                            }
                        } else {
                            write_line(&mut writer, format!("{} BAD Unsupported UID command", tag))
                                .await?;
                        }
                    }
                }
                "STORE" => {
                    if require_imap_auth(&mut writer, tag, &session).await? {
                        write_line(&mut writer, format!("{} OK STORE completed", tag)).await?;
                    }
                }
                "LOGOUT" => {
                    write_line(&mut writer, "* BYE Logging out").await?;
                    write_line(&mut writer, format!("{} OK LOGOUT completed", tag)).await?;
                    report_mail_command(
                        &ctx.callback_url,
                        &ctx.rule_id,
                        &ctx.node_id,
                        &client_ip,
                        client_port,
                        ctx.port,
                        &event_type,
                        "IMAP command: LOGOUT".to_string(),
                        &line,
                    );
                    break;
                }
                _ => write_line(&mut writer, format!("{} BAD Unsupported command", tag)).await?,
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
            format!("IMAP command: {}", line),
            &line,
        );
    }

    Ok(())
}

/// 开启 IMAP 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_imap_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimImapConfig,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(ImapContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });
    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation IMAP server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_imap_connection(conn_ctx, stream, peer).await {
                        error!("IMAP simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!("Simulation IMAP server for rule '{}' (ID: {}) on port {} gracefully shutting down...", name_str, rule_id, port);
                break;
            }
        }
    }
    Ok(())
}
