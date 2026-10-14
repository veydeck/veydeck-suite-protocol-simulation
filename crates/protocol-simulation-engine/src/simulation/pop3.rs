//! POP3 协议仿真运行器。

use super::config::SimPop3Config;
use super::mail_common::{
    MailMessage, credentials_match, custom_response, decode_auth_plain, read_line,
    report_mail_command, report_mail_connection, rfc822_message, write_line, write_raw,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::BufReader;
use tokio::sync::oneshot;
use tracing::{error, info};

struct Pop3Context {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimPop3Config,
}

struct Pop3Session {
    username: Option<String>,
    authed: bool,
    deleted: Vec<usize>,
}

impl Pop3Session {
    fn new(require_auth: bool, message_count: usize) -> Self {
        Self {
            username: None,
            authed: !require_auth,
            deleted: vec![0; message_count],
        }
    }

    fn is_deleted(&self, index: usize) -> bool {
        self.deleted.get(index).copied().unwrap_or(0) == 1
    }
}

fn pop3_message_size(message: &MailMessage) -> usize {
    rfc822_message(message).len()
}

fn visible_messages<'a>(
    messages: &'a [MailMessage],
    session: &'a Pop3Session,
) -> impl Iterator<Item = (usize, &'a MailMessage)> {
    messages
        .iter()
        .enumerate()
        .filter(|(index, _)| !session.is_deleted(*index))
}

fn parse_index(args: &str) -> Option<usize> {
    args.split_whitespace()
        .next()?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .map(|value| value - 1)
}

async fn ensure_auth(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    session: &Pop3Session,
) -> anyhow::Result<bool> {
    if session.authed {
        Ok(true)
    } else {
        write_line(writer, "-ERR Authentication required").await?;
        Ok(false)
    }
}

async fn handle_pop3_connection(
    ctx: Arc<Pop3Context>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let client_ip = peer.ip().to_string();
    let client_port = peer.port();
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let messages = ctx.config.messages.as_deref().unwrap_or(&[]);
    let credentials = ctx.config.credentials.as_deref().unwrap_or(&[]);
    let require_auth = ctx.config.require_auth.unwrap_or(false);
    let mut session = Pop3Session::new(require_auth, messages.len());

    let banner = ctx
        .config
        .banner
        .clone()
        .unwrap_or_else(|| "Veydeck POP3 service ready".to_string());
    write_line(&mut writer, format!("+OK {}", banner)).await?;
    report_mail_connection(
        &ctx.callback_url,
        &ctx.rule_id,
        &ctx.node_id,
        &client_ip,
        client_port,
        ctx.port,
        "POP3",
    );

    loop {
        let Some(line) = read_line(&mut reader).await? else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let (command, args) = line
            .split_once(' ')
            .map(|(command, args)| (command.to_ascii_uppercase(), args.trim().to_string()))
            .unwrap_or((line.to_ascii_uppercase(), String::new()));
        let mut event_type = "pop3_command".to_string();

        if let Some((response, custom_event)) = custom_response(
            ctx.config.custom_responses.as_deref(),
            &command,
            &line,
            "pop3_command",
        ) {
            event_type = custom_event;
            write_line(&mut writer, response).await?;
        } else {
            match command.as_str() {
                "CAPA" => {
                    write_line(&mut writer, "+OK Capability list follows").await?;
                    let caps = ctx.config.capabilities.clone().unwrap_or_else(|| {
                        vec!["USER".to_string(), "UIDL".to_string(), "TOP".to_string()]
                    });
                    for cap in caps {
                        write_line(&mut writer, cap).await?;
                    }
                    write_line(&mut writer, ".").await?;
                }
                "USER" => {
                    session.username = Some(args.clone());
                    event_type = "auth_attempt".to_string();
                    write_line(&mut writer, "+OK User accepted").await?;
                }
                "PASS" => {
                    event_type = "auth_attempt".to_string();
                    let username = session.username.as_deref().unwrap_or_default();
                    session.authed = credentials_match(credentials, username, &args);
                    if session.authed {
                        write_line(&mut writer, "+OK Mailbox locked and ready").await?;
                    } else {
                        write_line(&mut writer, "-ERR Invalid credentials").await?;
                    }
                }
                "AUTH" => {
                    event_type = "auth_attempt".to_string();
                    let mut parts = args.split_whitespace();
                    let mechanism = parts.next().unwrap_or_default().to_ascii_uppercase();
                    let initial = parts.next().unwrap_or_default();
                    if mechanism == "PLAIN" {
                        if initial.is_empty() {
                            write_line(&mut writer, "+").await?;
                            if let Some(auth_line) = read_line(&mut reader).await?
                                && let Some((username, password)) = decode_auth_plain(&auth_line)
                            {
                                session.authed =
                                    credentials_match(credentials, &username, &password);
                            }
                        } else if let Some((username, password)) = decode_auth_plain(initial) {
                            session.authed = credentials_match(credentials, &username, &password);
                        }
                    }
                    if session.authed {
                        write_line(&mut writer, "+OK Authentication successful").await?;
                    } else {
                        write_line(&mut writer, "-ERR Authentication failed").await?;
                    }
                }
                "STAT" => {
                    if ensure_auth(&mut writer, &session).await? {
                        let count = visible_messages(messages, &session).count();
                        let size: usize = visible_messages(messages, &session)
                            .map(|(_, message)| pop3_message_size(message))
                            .sum();
                        write_line(&mut writer, format!("+OK {} {}", count, size)).await?;
                    }
                }
                "LIST" => {
                    if ensure_auth(&mut writer, &session).await? {
                        if let Some(index) = parse_index(&args) {
                            if let Some(message) =
                                messages.get(index).filter(|_| !session.is_deleted(index))
                            {
                                write_line(
                                    &mut writer,
                                    format!("+OK {} {}", index + 1, pop3_message_size(message)),
                                )
                                .await?;
                            } else {
                                write_line(&mut writer, "-ERR No such message").await?;
                            }
                        } else {
                            write_line(&mut writer, "+OK Scan listing follows").await?;
                            for (index, message) in visible_messages(messages, &session) {
                                write_line(
                                    &mut writer,
                                    format!("{} {}", index + 1, pop3_message_size(message)),
                                )
                                .await?;
                            }
                            write_line(&mut writer, ".").await?;
                        }
                    }
                }
                "UIDL" => {
                    if ensure_auth(&mut writer, &session).await? {
                        if let Some(index) = parse_index(&args) {
                            if let Some(message) =
                                messages.get(index).filter(|_| !session.is_deleted(index))
                            {
                                write_line(
                                    &mut writer,
                                    format!(
                                        "+OK {} {}",
                                        index + 1,
                                        message.uid.as_deref().unwrap_or("veydeck-uid")
                                    ),
                                )
                                .await?;
                            } else {
                                write_line(&mut writer, "-ERR No such message").await?;
                            }
                        } else {
                            write_line(&mut writer, "+OK Unique-ID listing follows").await?;
                            for (index, message) in visible_messages(messages, &session) {
                                write_line(
                                    &mut writer,
                                    format!(
                                        "{} {}",
                                        index + 1,
                                        message.uid.as_deref().unwrap_or("veydeck-uid")
                                    ),
                                )
                                .await?;
                            }
                            write_line(&mut writer, ".").await?;
                        }
                    }
                }
                "RETR" | "TOP" => {
                    if ensure_auth(&mut writer, &session).await? {
                        if let Some(index) = parse_index(&args) {
                            if let Some(message) =
                                messages.get(index).filter(|_| !session.is_deleted(index))
                            {
                                event_type = "exploit_attempt".to_string();
                                let body = rfc822_message(message);
                                write_line(&mut writer, format!("+OK {} octets", body.len()))
                                    .await?;
                                write_raw(&mut writer, body).await?;
                                write_line(&mut writer, ".").await?;
                            } else {
                                write_line(&mut writer, "-ERR No such message").await?;
                            }
                        } else {
                            write_line(&mut writer, "-ERR Message number required").await?;
                        }
                    }
                }
                "DELE" => {
                    if ensure_auth(&mut writer, &session).await? {
                        if let Some(index) = parse_index(&args) {
                            if index < session.deleted.len() {
                                session.deleted[index] = 1;
                                write_line(&mut writer, "+OK Message marked deleted").await?;
                            } else {
                                write_line(&mut writer, "-ERR No such message").await?;
                            }
                        } else {
                            write_line(&mut writer, "-ERR Message number required").await?;
                        }
                    }
                }
                "RSET" => {
                    session.deleted.fill(0);
                    write_line(&mut writer, "+OK Reset state").await?;
                }
                "NOOP" => write_line(&mut writer, "+OK").await?,
                "QUIT" => {
                    write_line(&mut writer, "+OK Bye").await?;
                    report_mail_command(
                        &ctx.callback_url,
                        &ctx.rule_id,
                        &ctx.node_id,
                        &client_ip,
                        client_port,
                        ctx.port,
                        &event_type,
                        "POP3 command: QUIT".to_string(),
                        &line,
                    );
                    break;
                }
                _ => write_line(&mut writer, "-ERR Unknown command").await?,
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
            format!("POP3 command: {}", line),
            &line,
        );
    }

    Ok(())
}

/// 开启 POP3 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_pop3_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimPop3Config,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(Pop3Context {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });
    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation POP3 server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_pop3_connection(conn_ctx, stream, peer).await {
                        error!("POP3 simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!("Simulation POP3 server for rule '{}' (ID: {}) on port {} gracefully shutting down...", name_str, rule_id, port);
                break;
            }
        }
    }
    Ok(())
}
