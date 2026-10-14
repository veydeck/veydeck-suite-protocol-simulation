use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimMqttConfig;
use anyhow::Context as _;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const MAX_PACKET_SIZE: usize = 64 * 1024;

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config: SimMqttConfig,
}

async fn read_packet(stream: &mut TcpStream) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
    let first = match stream.read_u8().await {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut multiplier = 1_usize;
    let mut remaining = 0_usize;
    for index in 0..4 {
        let encoded = stream.read_u8().await?;
        remaining += usize::from(encoded & 0x7f) * multiplier;
        if encoded & 0x80 == 0 {
            break;
        }
        if index == 3 {
            anyhow::bail!("MQTT remaining length exceeds four bytes");
        }
        multiplier *= 128;
    }
    if remaining > MAX_PACKET_SIZE {
        anyhow::bail!("MQTT packet exceeds maximum size");
    }
    let mut payload = vec![0_u8; remaining];
    stream.read_exact(&mut payload).await?;
    Ok(Some((first, payload)))
}

fn parse_connect(payload: &[u8]) -> anyhow::Result<(u8, bool)> {
    if payload.len() < 7 {
        anyhow::bail!("MQTT CONNECT packet is truncated");
    }
    let name_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    if 2 + name_len + 2 > payload.len() {
        anyhow::bail!("MQTT protocol name is truncated");
    }
    let name = &payload[2..2 + name_len];
    if name != b"MQTT" && name != b"MQIsdp" {
        anyhow::bail!("MQTT CONNECT contains an unsupported protocol name");
    }
    let level = payload[2 + name_len];
    let flags = payload[3 + name_len];
    Ok((level, flags & 0xc0 != 0))
}

fn connack(level: u8, accepted: bool) -> Vec<u8> {
    if level == 5 {
        vec![0x20, 0x03, 0x00, if accepted { 0x00 } else { 0x87 }, 0x00]
    } else {
        vec![0x20, 0x02, 0x00, if accepted { 0x00 } else { 0x05 }]
    }
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    while let Some((header, payload)) = read_packet(&mut stream).await? {
        let packet_type = header >> 4;
        match packet_type {
            1 => {
                let (level, has_credentials) = parse_connect(&payload)?;
                let accepted = matches!(level, 4 | 5)
                    && (ctx.config.allow_anonymous.unwrap_or(true) || has_credentials);
                stream.write_all(&connack(level, accepted)).await?;
                report_sim_log_async(
                    ctx.callback_url.clone(),
                    SimLogDraft {
                        rule_id: ctx.rule_id.clone(),
                        node_id: ctx.node_id.clone(),
                        client_ip: peer.ip().to_string(),
                        client_port: peer.port(),
                        server_port: ctx.port,
                        event_type: "mqtt_connect".to_string(),
                        detail_summary: format!(
                            "MQTT protocol level {level} CONNECT {}",
                            if accepted { "accepted" } else { "rejected" }
                        ),
                        payload_hex: None,
                    },
                );
                if !accepted {
                    return Ok(());
                }
            }
            12 => {
                if !payload.is_empty() {
                    anyhow::bail!("MQTT PINGREQ must not contain a payload");
                }
                stream.write_all(&[0xd0, 0x00]).await?;
                report_control(&ctx, peer, "PINGREQ", Some(&[header]));
            }
            14 => {
                report_control(&ctx, peer, "DISCONNECT", Some(&[header]));
                return Ok(());
            }
            _ => {
                report_control(&ctx, peer, &format!("packet type {packet_type}"), None);
            }
        }
    }
    Ok(())
}

fn report_control(ctx: &Context, peer: SocketAddr, name: &str, payload: Option<&[u8]>) {
    report_sim_log_async(
        ctx.callback_url.clone(),
        SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: ctx.port,
            event_type: "mqtt_control".to_string(),
            detail_summary: format!("MQTT {name} received"),
            payload_hex: payload.map(encode_hex),
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub async fn start_mqtt_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimMqttConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "MQTT simulation started");
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
                let (stream, peer) = accepted.context("failed to accept MQTT connection")?;
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(30), handle(ctx, stream, peer)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "MQTT connection ended with error"),
                        Err(_) => tracing::debug!(%peer, "MQTT connection timed out"),
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
    fn parses_mqtt_311_connect_probe() {
        let payload = b"\0\x04MQTT\x04\x02\0\x1e\0\x04nmap";
        assert_eq!(parse_connect(payload).unwrap(), (4, false));
        assert_eq!(connack(4, true), [0x20, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn mqtt_five_connack_contains_empty_properties() {
        assert_eq!(connack(5, true), [0x20, 0x03, 0x00, 0x00, 0x00]);
    }
}
