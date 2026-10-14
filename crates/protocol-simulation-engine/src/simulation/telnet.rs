use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimTelnetConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config: SimTelnetConfig,
}

fn report(ctx: &Context, peer: SocketAddr, event_type: &str, summary: String, payload: &[u8]) {
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: ctx.port,
            event_type: event_type.to_string(),
            detail_summary: summary,
            payload_hex: (!payload.is_empty())
                .then(|| encode_hex(&payload[..payload.len().min(512)])),
        },
    );
}

async fn handle(ctx: Arc<Context>, stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    report(
        &ctx,
        peer,
        "connection",
        "Telnet client connected".to_string(),
        &[],
    );
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    let banner = ctx
        .config
        .banner
        .as_deref()
        .unwrap_or("Ubuntu 22.04 LTS\r\n");
    write.write_all(banner.as_bytes()).await?;
    write.write_all(b"login: ").await?;
    let username = lines.next_line().await?.unwrap_or_default();
    write.write_all(b"Password: ").await?;
    let password = lines.next_line().await?.unwrap_or_default();
    let valid = ctx.config.credentials.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|item| item.username == username.trim() && item.password == password.trim())
    });
    report(
        &ctx,
        peer,
        "auth_attempt",
        format!(
            "Telnet login attempt for user {} ({})",
            username.trim(),
            if valid { "accepted" } else { "rejected" }
        ),
        username.as_bytes(),
    );
    if !valid {
        write.write_all(b"\r\nLogin incorrect\r\n").await?;
        return Ok(());
    }
    let prompt = ctx.config.prompt.as_deref().unwrap_or("$ ");
    write.write_all(format!("\r\n{prompt}").as_bytes()).await?;
    while let Some(line) = lines.next_line().await? {
        let command = line.trim();
        report(
            &ctx,
            peer,
            "command",
            format!("Telnet command: {command}"),
            command.as_bytes(),
        );
        if matches!(command, "exit" | "logout") {
            write.write_all(b"logout\r\n").await?;
            break;
        }
        let response = ctx
            .config
            .command_responses
            .as_ref()
            .and_then(|responses| responses.get(command))
            .map(String::as_str)
            .unwrap_or("command not found");
        write
            .write_all(format!("{response}\r\n{prompt}").as_bytes())
            .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_telnet_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimTelnetConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "Telnet simulation started");
    let ctx = Arc::new(Context {
        rule_id,
        callback_url,
        node_id,
        port,
        config,
    });
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result?;
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(error) = handle(ctx, stream, peer).await {
                        tracing::debug!(%peer, %error, "Telnet connection ended with error");
                    }
                });
            }
            _ = &mut shutdown_rx => break,
        }
    }
    Ok(())
}
