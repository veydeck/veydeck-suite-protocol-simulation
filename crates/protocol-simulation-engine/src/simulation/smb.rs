use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimSmbConfig;
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
    config: SimSmbConfig,
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    let mut buffer = vec![0; 8192];
    let read = stream.read(&mut buffer).await?;
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: ctx.port,
            event_type: "connection".to_string(),
            detail_summary: format!(
                "SMB negotiate request received for server {}",
                ctx.config.server_name.as_deref().unwrap_or("Veydeck")
            ),
            payload_hex: (read > 0).then(|| encode_hex(&buffer[..read.min(512)])),
        },
    );
    if read < 8 {
        return Ok(());
    }
    // NetBIOS framing + SMB2 negotiate response header. It is deliberately limited to
    // negotiation so clients identify the service without granting file access.
    let mut body = vec![0xfe, b'S', b'M', b'B'];
    body.extend_from_slice(&64_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&0xc000_0022_u32.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&1_u32.to_le_bytes());
    body.resize(64, 0);
    let len = body.len();
    let framing = [0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    stream.write_all(&framing).await?;
    stream.write_all(&body).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_smb_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimSmbConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "SMB simulation started");
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
                tokio::spawn(async move { if let Err(error) = handle(ctx, stream, peer).await {
                    tracing::debug!(%peer, %error, "SMB connection ended with error");
                }});
            }
            _ = &mut shutdown_rx => break,
        }
    }
    Ok(())
}
