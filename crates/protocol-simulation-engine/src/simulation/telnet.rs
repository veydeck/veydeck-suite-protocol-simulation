use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimTelnetConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
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

async fn read_telnet_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> anyhow::Result<Option<String>> {
    tokio::time::timeout(super::wire::IDLE_TIMEOUT, async {
        let mut value = Vec::new();
        loop {
            let byte = match reader.read_u8().await {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && value.is_empty() => {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            };
            match byte {
                255 => {
                    let command = reader.read_u8().await?;
                    match command {
                        251..=254 => {
                            reader.read_u8().await?;
                        }
                        250 => {
                            let mut last = 0;
                            let mut ended = false;
                            for _ in 0..8192 {
                                let next = reader.read_u8().await?;
                                if last == 255 && next == 240 {
                                    ended = true;
                                    break;
                                }
                                last = next;
                            }
                            anyhow::ensure!(ended, "oversized Telnet subnegotiation");
                        }
                        255 => value.push(255),
                        _ => {}
                    }
                }
                b'\n' => {
                    return Ok(Some(
                        String::from_utf8(value)?.trim_end_matches('\r').to_string(),
                    ));
                }
                0 => {}
                value_byte => value.push(value_byte),
            }
            anyhow::ensure!(value.len() <= 8192, "Telnet line too long");
        }
    })
    .await?
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
    let mut reader = BufReader::new(read);
    let banner = ctx.config.banner.as_deref().unwrap_or("Ubuntu 22.04 LTS");
    let greeting = [
        &[255, 251, 1, 255, 251, 3, 255, 252, 34][..],
        banner.as_bytes(),
        b"\r\nlogin: ",
    ]
    .concat();
    write.write_all(&greeting).await?;
    let username = read_telnet_line(&mut reader).await?.unwrap_or_default();
    write.write_all(b"Password: ").await?;
    let password = read_telnet_line(&mut reader).await?.unwrap_or_default();
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
    while let Some(line) = read_telnet_line(&mut reader).await? {
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
