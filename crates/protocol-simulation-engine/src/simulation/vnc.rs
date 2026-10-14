use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimVncConfig;
use anyhow::Context as _;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    protocol_version: String,
    security_types: Vec<u8>,
}

fn normalize_config(config: SimVncConfig) -> anyhow::Result<(String, Vec<u8>)> {
    let version = config.protocol_version.unwrap_or_else(|| "3.8".to_string());
    if !matches!(version.as_str(), "3.3" | "3.7" | "3.8") {
        anyhow::bail!("VNC protocol_version must be 3.3, 3.7, or 3.8");
    }
    let names = config
        .security_types
        .unwrap_or_else(|| vec!["none".to_string()]);
    let mut types = Vec::new();
    for name in names {
        let value = match name.trim().to_ascii_lowercase().as_str() {
            "none" => 1,
            "vnc_auth" | "vnc-auth" => 2,
            _ => anyhow::bail!("unsupported VNC security type: {name}"),
        };
        if !types.contains(&value) {
            types.push(value);
        }
    }
    if types.is_empty() {
        anyhow::bail!("VNC security_types cannot be empty");
    }
    Ok((version, types))
}

fn banner(version: &str) -> String {
    let minor = match version {
        "3.3" => "003",
        "3.7" => "007",
        _ => "008",
    };
    format!("RFB 003.{minor}\n")
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    stream
        .write_all(banner(&ctx.protocol_version).as_bytes())
        .await?;
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: ctx.port,
            event_type: "vnc_handshake".to_string(),
            detail_summary: format!("VNC RFB {} handshake probe", ctx.protocol_version),
            payload_hex: None,
        },
    );
    let mut client_banner = [0_u8; 12];
    stream
        .read_exact(&mut client_banner)
        .await
        .context("failed to read VNC client protocol version")?;
    if !client_banner.starts_with(b"RFB ") || client_banner[11] != b'\n' {
        anyhow::bail!("invalid VNC client protocol version");
    }

    let selected = if ctx.protocol_version == "3.3" {
        stream
            .write_all(&u32::from(ctx.security_types[0]).to_be_bytes())
            .await?;
        ctx.security_types[0]
    } else {
        stream
            .write_u8(u8::try_from(ctx.security_types.len())?)
            .await?;
        stream.write_all(&ctx.security_types).await?;
        let selected = stream.read_u8().await?;
        if !ctx.security_types.contains(&selected) {
            anyhow::bail!("client selected an unadvertised VNC security type");
        }
        selected
    };
    match selected {
        1 => {
            if ctx.protocol_version != "3.3" {
                stream.write_all(&0_u32.to_be_bytes()).await?;
            }
        }
        2 => {
            stream.write_all(b"VeydeckVNCProbe!").await?;
            let mut response = [0_u8; 16];
            stream.read_exact(&mut response).await?;
            stream.write_all(&1_u32.to_be_bytes()).await?;
            if ctx.protocol_version == "3.8" {
                let reason = b"Authentication unavailable in protocol simulation";
                stream
                    .write_all(&u32::try_from(reason.len())?.to_be_bytes())
                    .await?;
                stream.write_all(reason).await?;
            }
        }
        _ => unreachable!("security types are validated"),
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_vnc_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimVncConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let (protocol_version, security_types) = normalize_config(config)?;
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "VNC simulation started");
    let ctx = Arc::new(Context {
        rule_id,
        callback_url,
        node_id,
        port,
        protocol_version,
        security_types,
    });
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept VNC connection")?;
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(30), handle(ctx, stream, peer)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "VNC connection ended with error"),
                        Err(_) => tracing::debug!(%peer, "VNC connection timed out"),
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
    fn builds_standard_rfb_banners() {
        assert_eq!(banner("3.3"), "RFB 003.003\n");
        assert_eq!(banner("3.8"), "RFB 003.008\n");
    }

    #[test]
    fn accepts_only_supported_security_types() {
        let (_, types) = normalize_config(SimVncConfig {
            protocol_version: Some("3.8".to_string()),
            security_types: Some(vec!["none".to_string(), "vnc_auth".to_string()]),
        })
        .unwrap();
        assert_eq!(types, [1, 2]);
    }
}
