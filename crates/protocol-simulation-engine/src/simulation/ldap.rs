use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimLdapConfig;
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
    config: SimLdapConfig,
}

fn ldap_message_id(bytes: &[u8]) -> u8 {
    bytes
        .windows(3)
        .find_map(|window| (window[0] == 0x02 && window[1] == 0x01).then_some(window[2]))
        .unwrap_or(1)
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    let mut buffer = vec![0; 8192];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let payload = &buffer[..read];
        let (event_type, operation, app_tag) = if payload.contains(&0x60) {
            ("auth_attempt", "LDAP bind request", 0x61)
        } else if payload.contains(&0x63) {
            ("query", "LDAP search request", 0x65)
        } else {
            ("command", "LDAP operation", 0x65)
        };
        report_sim_log_async(
            ctx.callback_url.clone(),
            SimLogDraft {
                rule_id: ctx.rule_id.clone(),
                node_id: ctx.node_id.clone(),
                client_ip: peer.ip().to_string(),
                client_port: peer.port(),
                server_port: ctx.port,
                event_type: event_type.to_string(),
                detail_summary: format!("{operation} under {}", ctx.config.base_dn),
                payload_hex: Some(encode_hex(&payload[..payload.len().min(512)])),
            },
        );
        let message_id = ldap_message_id(payload);
        // BindResponse/SearchResultDone: success, empty matched DN and diagnostic message.
        stream
            .write_all(&[
                0x30, 0x0c, 0x02, 0x01, message_id, app_tag, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00,
                0x04, 0x00,
            ])
            .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_ldap_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimLdapConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "LDAP simulation started");
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
                    tracing::debug!(%peer, %error, "LDAP connection ended with error");
                }});
            }
            _ = &mut shutdown_rx => break,
        }
    }
    Ok(())
}
