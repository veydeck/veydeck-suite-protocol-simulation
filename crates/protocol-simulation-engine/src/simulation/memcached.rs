use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimMemcachedConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const MAX_REQUEST_SIZE: usize = 4096;

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config: SimMemcachedConfig,
}

fn stats_response(config: &SimMemcachedConfig, settings: bool) -> String {
    if settings {
        return "STAT maxbytes 67108864\r\nSTAT maxconns 1024\r\nSTAT tcpport 11211\r\nEND\r\n"
            .to_string();
    }
    let version = config.server_version.as_deref().unwrap_or("1.6.24");
    let mut response = format!(
        "STAT pid 1\r\nSTAT uptime 3600\r\nSTAT time 1700000000\r\nSTAT version {version}\r\nSTAT pointer_size 64\r\nSTAT curr_connections 1\r\nSTAT total_connections 1\r\nSTAT maxconns 1024\r\n"
    );
    if let Some(stats) = &config.stats {
        for (key, value) in stats {
            if !key.trim().is_empty() && !key.chars().any(char::is_whitespace) {
                response.push_str(&format!("STAT {key} {value}\r\n"));
            }
        }
    }
    response.push_str("END\r\n");
    response
}

fn response_for(command: &str, config: &SimMemcachedConfig) -> String {
    let normalized = command.trim().to_ascii_lowercase();
    if normalized == "version" {
        format!(
            "VERSION {}\r\n",
            config.server_version.as_deref().unwrap_or("1.6.24")
        )
    } else if normalized == "stats" {
        stats_response(config, false)
    } else if normalized == "stats settings" {
        stats_response(config, true)
    } else {
        "ERROR\r\n".to_string()
    }
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    let mut pending = Vec::new();
    let mut chunk = [0_u8; 512];
    let mut commands = 0_usize;
    loop {
        let size = stream.read(&mut chunk).await?;
        if size == 0 {
            return Ok(());
        }
        pending.extend_from_slice(&chunk[..size]);
        if pending.len() > MAX_REQUEST_SIZE {
            anyhow::bail!("Memcached command exceeds maximum size");
        }
        while let Some(line_end) = pending.iter().position(|byte| *byte == b'\n') {
            let line = pending.drain(..=line_end).collect::<Vec<_>>();
            let command = String::from_utf8_lossy(&line);
            if command.trim().is_empty() {
                continue;
            }
            stream
                .write_all(response_for(&command, &ctx.config).as_bytes())
                .await?;
            report_sim_log_async(
                ctx.callback_url.clone(),
                SimLogDraft {
                    rule_id: ctx.rule_id.clone(),
                    node_id: ctx.node_id.clone(),
                    client_ip: peer.ip().to_string(),
                    client_port: peer.port(),
                    server_port: ctx.port,
                    event_type: "memcached_command".to_string(),
                    detail_summary: format!(
                        "Memcached probe command: {}",
                        command.split_whitespace().next().unwrap_or("unknown")
                    ),
                    payload_hex: None,
                },
            );
            commands += 1;
            if commands >= 32 {
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_memcached_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimMemcachedConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "Memcached simulation started");
    let ctx = Arc::new(Context {
        rule_id,
        callback_url,
        node_id,
        port,
        config,
    });
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(30), handle(ctx, stream, peer)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "Memcached connection ended with error"),
                        Err(_) => tracing::debug!(%peer, "Memcached connection timed out"),
                    }
                });
            }
            _ = &mut shutdown_rx => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_response_starts_with_identifiable_fields() {
        let response = stats_response(
            &SimMemcachedConfig {
                server_version: Some("1.6.24".to_string()),
                stats: None,
            },
            false,
        );
        assert!(response.starts_with("STAT pid 1\r\nSTAT uptime 3600\r\n"));
        assert!(response.contains("STAT version 1.6.24\r\n"));
        assert!(response.ends_with("END\r\n"));
    }

    #[test]
    fn version_command_uses_configured_version() {
        let response = response_for(
            "version\r\n",
            &SimMemcachedConfig {
                server_version: Some("1.6.32".to_string()),
                stats: None,
            },
        );
        assert_eq!(response, "VERSION 1.6.32\r\n");
    }
}
