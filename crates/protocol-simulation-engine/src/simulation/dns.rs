use super::common::{SimLogDraft, encode_hex, report_sim_log_for_endpoint_async};
use super::config::SimDnsConfig;
use anyhow::Context;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;

const MAX_DNS_MESSAGE_SIZE: usize = 4096;

#[derive(Clone)]
struct DnsRuntime {
    rule_id: String,
    node_id: String,
    callback_url: String,
    endpoint_id: String,
    server_port: u16,
    config: SimDnsConfig,
    transport: &'static str,
}

#[allow(clippy::too_many_arguments)]
pub async fn start_dns_tcp_simulation(
    rule_id: String,
    rule_name: Option<String>,
    endpoint_id: String,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimDnsConfig,
    listener: TcpListener,
    mut shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    validate_config(&config)?;
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "DNS TCP simulation started");
    let runtime = DnsRuntime {
        rule_id,
        node_id,
        callback_url,
        endpoint_id,
        server_port: port,
        config,
        transport: "TCP",
    };

    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept DNS TCP connection")?;
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_tcp_connection(stream, peer, runtime).await {
                        tracing::debug!(%peer, %error, "DNS TCP connection ended with error");
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_dns_udp_simulation(
    rule_id: String,
    rule_name: Option<String>,
    endpoint_id: String,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimDnsConfig,
    socket: UdpSocket,
    mut shutdown: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    validate_config(&config)?;
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "DNS UDP simulation started");
    let runtime = DnsRuntime {
        rule_id,
        node_id,
        callback_url,
        endpoint_id,
        server_port: port,
        config,
        transport: "UDP",
    };
    let mut buffer = [0_u8; MAX_DNS_MESSAGE_SIZE];

    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = received.context("failed to receive DNS UDP query")?;
                let query = &buffer[..size];
                match build_response(query, &runtime.config) {
                    Ok((response, name)) => {
                        socket.send_to(&response, peer).await.context("failed to send DNS UDP response")?;
                        report_query(&runtime, peer, query, &name);
                    }
                    Err(error) => tracing::debug!(%peer, %error, "ignored malformed DNS UDP query"),
                }
            }
        }
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    runtime: DnsRuntime,
) -> anyhow::Result<()> {
    loop {
        let size = match stream.read_u16().await {
            Ok(size) => usize::from(size),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error).context("failed to read DNS TCP message length"),
        };
        if size == 0 || size > MAX_DNS_MESSAGE_SIZE {
            anyhow::bail!("invalid DNS TCP message length: {size}");
        }
        let mut query = vec![0_u8; size];
        stream
            .read_exact(&mut query)
            .await
            .context("failed to read DNS TCP query")?;
        let (response, name) = build_response(&query, &runtime.config)?;
        stream.write_u16(u16::try_from(response.len())?).await?;
        stream.write_all(&response).await?;
        report_query(&runtime, peer, &query, &name);
    }
}

fn report_query(runtime: &DnsRuntime, peer: SocketAddr, payload: &[u8], name: &str) {
    report_sim_log_for_endpoint_async(
        runtime.callback_url.clone(),
        SimLogDraft {
            rule_id: runtime.rule_id.clone(),
            node_id: runtime.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: runtime.server_port,
            event_type: "query".to_string(),
            detail_summary: format!("DNS {} A query for {name}", runtime.transport),
            payload_hex: Some(encode_hex(payload)),
        },
        runtime.endpoint_id.clone(),
    );
}

fn validate_config(config: &SimDnsConfig) -> anyhow::Result<()> {
    for (name, address) in &config.records {
        if name.trim().is_empty() {
            anyhow::bail!("DNS record name cannot be empty");
        }
        address
            .parse::<Ipv4Addr>()
            .with_context(|| format!("DNS record {name} must contain a valid IPv4 address"))?;
    }
    if let Some(address) = &config.default_ipv4 {
        address
            .parse::<Ipv4Addr>()
            .context("DNS default_ipv4 must be a valid IPv4 address")?;
    }
    Ok(())
}

fn build_response(query: &[u8], config: &SimDnsConfig) -> anyhow::Result<(Vec<u8>, String)> {
    if query.len() < 12 {
        anyhow::bail!("DNS query is shorter than its header");
    }
    let question_count = u16::from_be_bytes([query[4], query[5]]);
    if question_count != 1 {
        anyhow::bail!("DNS simulation accepts exactly one question");
    }
    let (name, name_end) = decode_name(query, 12)?;
    if name_end + 4 > query.len() {
        anyhow::bail!("DNS question is truncated");
    }
    let question_end = name_end + 4;
    let query_type = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
    let query_class = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
    let normalized = name.trim_end_matches('.').to_ascii_lowercase();
    let address = config
        .records
        .iter()
        .find(|(record, _)| {
            record
                .trim_end_matches('.')
                .eq_ignore_ascii_case(&normalized)
        })
        .map(|(_, address)| address)
        .or(config.default_ipv4.as_ref())
        .and_then(|address| address.parse::<Ipv4Addr>().ok());
    let has_answer = query_type == 1 && query_class == 1 && address.is_some();

    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(if address.is_some() {
        &[0x81, 0x80]
    } else {
        &[0x81, 0x83]
    });
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&(u16::from(has_answer)).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    if let Some(address) = address.filter(|_| has_answer) {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&config.ttl.unwrap_or(60).to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address.octets());
    }
    Ok((response, normalized))
}

fn decode_name(message: &[u8], mut offset: usize) -> anyhow::Result<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let length = *message.get(offset).context("DNS name is truncated")? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + length > message.len() {
            anyhow::bail!("DNS name contains an invalid label");
        }
        labels.push(std::str::from_utf8(&message[offset..offset + length])?.to_string());
        offset += length;
    }
    Ok((labels.join("."), offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn query(name: &str) -> Vec<u8> {
        let mut bytes = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
        bytes
    }

    #[test]
    fn builds_a_record_response() {
        let config = SimDnsConfig {
            records: BTreeMap::from([("dns.veydeck.local".to_string(), "192.0.2.53".to_string())]),
            default_ipv4: None,
            ttl: Some(120),
        };
        let (response, name) = build_response(&query("dns.veydeck.local"), &config).unwrap();
        assert_eq!(name, "dns.veydeck.local");
        assert_eq!(&response[6..8], &[0, 1]);
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 53]);
    }
}
