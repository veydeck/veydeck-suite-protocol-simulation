use super::common::{SimLogDraft, report_sim_log_for_endpoint_async};
use super::config::SimSnmpConfig;
use anyhow::Context as _;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

const MAX_SNMP_MESSAGE_SIZE: usize = 8192;
const MAX_VARBINDS: usize = 32;

#[derive(Debug)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

#[derive(Debug)]
struct SnmpRequest {
    version: i64,
    community: Vec<u8>,
    pdu_tag: u8,
    request_id: i64,
    max_repetitions: usize,
    oids: Vec<Vec<u32>>,
}

struct Runtime {
    rule_id: String,
    callback_url: String,
    node_id: String,
    endpoint_id: String,
    port: u16,
    community: String,
    values: BTreeMap<Vec<u32>, String>,
}

fn read_length(input: &[u8], cursor: &mut usize) -> anyhow::Result<usize> {
    let first = *input.get(*cursor).context("BER length is truncated")?;
    *cursor += 1;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 || *cursor + count > input.len() {
        anyhow::bail!("unsupported BER length encoding");
    }
    let mut length = 0_usize;
    for byte in &input[*cursor..*cursor + count] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .context("BER length overflows usize")?;
    }
    *cursor += count;
    Ok(length)
}

fn read_tlv<'a>(input: &'a [u8], cursor: &mut usize) -> anyhow::Result<Tlv<'a>> {
    let tag = *input.get(*cursor).context("BER tag is truncated")?;
    *cursor += 1;
    let length = read_length(input, cursor)?;
    let end = cursor.checked_add(length).context("BER length overflow")?;
    let value = input.get(*cursor..end).context("BER value is truncated")?;
    *cursor = end;
    Ok(Tlv { tag, value })
}

fn decode_integer(bytes: &[u8]) -> anyhow::Result<i64> {
    if bytes.is_empty() || bytes.len() > 8 {
        anyhow::bail!("unsupported BER integer length");
    }
    let mut value = if bytes[0] & 0x80 != 0 { -1_i64 } else { 0 };
    for byte in bytes {
        value = (value << 8) | i64::from(*byte);
    }
    Ok(value)
}

fn decode_oid(bytes: &[u8]) -> anyhow::Result<Vec<u32>> {
    let first = *bytes.first().context("OID is empty")?;
    let first_component = u32::from(first / 40).min(2);
    let mut oid = vec![first_component, u32::from(first) - first_component * 40];
    let mut value = 0_u32;
    let mut pending = false;
    for byte in &bytes[1..] {
        value = value
            .checked_mul(128)
            .and_then(|current| current.checked_add(u32::from(byte & 0x7f)))
            .context("OID component overflows u32")?;
        pending = byte & 0x80 != 0;
        if !pending {
            oid.push(value);
            value = 0;
        }
    }
    if pending {
        anyhow::bail!("OID component is truncated");
    }
    Ok(oid)
}

fn parse_request(message: &[u8]) -> anyhow::Result<SnmpRequest> {
    let mut cursor = 0;
    let envelope = read_tlv(message, &mut cursor)?;
    if envelope.tag != 0x30 || cursor != message.len() {
        anyhow::bail!("SNMP message must contain one BER sequence");
    }
    let mut message_cursor = 0;
    let version = read_tlv(envelope.value, &mut message_cursor)?;
    let community = read_tlv(envelope.value, &mut message_cursor)?;
    let pdu = read_tlv(envelope.value, &mut message_cursor)?;
    if version.tag != 0x02 || community.tag != 0x04 || !matches!(pdu.tag, 0xa0 | 0xa1 | 0xa5) {
        anyhow::bail!("unsupported SNMP message structure");
    }
    let version = decode_integer(version.value)?;
    if !matches!(version, 0 | 1) {
        anyhow::bail!("only SNMP v1 and v2c are supported");
    }

    let mut pdu_cursor = 0;
    let request_id = read_tlv(pdu.value, &mut pdu_cursor)?;
    let first_control = read_tlv(pdu.value, &mut pdu_cursor)?;
    let second_control = read_tlv(pdu.value, &mut pdu_cursor)?;
    let varbind_list = read_tlv(pdu.value, &mut pdu_cursor)?;
    if request_id.tag != 0x02
        || first_control.tag != 0x02
        || second_control.tag != 0x02
        || varbind_list.tag != 0x30
    {
        anyhow::bail!("invalid SNMP request PDU");
    }
    let max_repetitions = if pdu.tag == 0xa5 {
        usize::try_from(decode_integer(second_control.value)?.max(0))?.min(MAX_VARBINDS)
    } else {
        1
    };
    let mut oids = Vec::new();
    let mut list_cursor = 0;
    while list_cursor < varbind_list.value.len() {
        if oids.len() >= MAX_VARBINDS {
            anyhow::bail!("SNMP request contains too many varbinds");
        }
        let varbind = read_tlv(varbind_list.value, &mut list_cursor)?;
        if varbind.tag != 0x30 {
            anyhow::bail!("SNMP varbind must be a sequence");
        }
        let mut varbind_cursor = 0;
        let oid = read_tlv(varbind.value, &mut varbind_cursor)?;
        let _value = read_tlv(varbind.value, &mut varbind_cursor)?;
        if oid.tag != 0x06 {
            anyhow::bail!("SNMP varbind does not contain an OID");
        }
        oids.push(decode_oid(oid.value)?);
    }
    if oids.is_empty() {
        anyhow::bail!("SNMP request does not contain a varbind");
    }
    Ok(SnmpRequest {
        version,
        community: community.value.to_vec(),
        pdu_tag: pdu.tag,
        request_id: decode_integer(request_id.value)?,
        max_repetitions,
        oids,
    })
}

fn encode_length(length: usize, output: &mut Vec<u8>) {
    if length < 128 {
        output.push(length as u8);
        return;
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first..];
    output.push(0x80 | significant.len() as u8);
    output.extend_from_slice(significant);
}

fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(content.len() + 6);
    output.push(tag);
    encode_length(content.len(), &mut output);
    output.extend_from_slice(content);
    output
}

fn encode_integer(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut first = 0;
    while first < bytes.len() - 1
        && ((bytes[first] == 0 && bytes[first + 1] & 0x80 == 0)
            || (bytes[first] == 0xff && bytes[first + 1] & 0x80 != 0))
    {
        first += 1;
    }
    wrap(0x02, &bytes[first..])
}

fn encode_unsigned(tag: u8, value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut content = bytes[first..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    wrap(tag, &content)
}

fn encode_oid(oid: &[u32]) -> anyhow::Result<Vec<u8>> {
    if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
        anyhow::bail!("invalid OID prefix");
    }
    let mut content = vec![u8::try_from(oid[0] * 40 + oid[1])?];
    for component in &oid[2..] {
        let mut encoded = [0_u8; 5];
        let mut index = encoded.len() - 1;
        encoded[index] = (component & 0x7f) as u8;
        let mut remaining = component >> 7;
        while remaining > 0 {
            index -= 1;
            encoded[index] = ((remaining & 0x7f) as u8) | 0x80;
            remaining >>= 7;
        }
        content.extend_from_slice(&encoded[index..]);
    }
    Ok(wrap(0x06, &content))
}

fn parse_oid_text(value: &str) -> anyhow::Result<Vec<u32>> {
    value
        .trim()
        .trim_start_matches('.')
        .split('.')
        .map(|part| {
            part.parse::<u32>()
                .context("OID contains a non-numeric component")
        })
        .collect()
}

fn build_values(config: &SimSnmpConfig) -> anyhow::Result<BTreeMap<Vec<u32>, String>> {
    let mut values = BTreeMap::new();
    values.insert(
        parse_oid_text("1.3.6.1.2.1.1.1.0")?,
        config
            .system_description
            .clone()
            .unwrap_or_else(|| "Linux veydeck-snmp 6.8.0".to_string()),
    );
    values.insert(parse_oid_text("1.3.6.1.2.1.1.3.0")?, "360000".to_string());
    values.insert(
        parse_oid_text("1.3.6.1.2.1.1.5.0")?,
        config
            .system_name
            .clone()
            .unwrap_or_else(|| "snmp-veydeck".to_string()),
    );
    values.insert(
        parse_oid_text("1.3.6.1.2.1.1.6.0")?,
        config
            .system_location
            .clone()
            .unwrap_or_else(|| "Veydeck".to_string()),
    );
    if let Some(custom) = &config.oids {
        for (oid, value) in custom {
            values.insert(parse_oid_text(oid)?, value.clone());
        }
    }
    Ok(values)
}

fn next_value<'a>(
    values: &'a BTreeMap<Vec<u32>, String>,
    oid: &[u32],
) -> Option<(&'a Vec<u32>, &'a String)> {
    values
        .iter()
        .find(|(candidate, _)| candidate.as_slice() > oid)
}

fn encode_varbind(oid: &[u32], value: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let mut content = encode_oid(oid)?;
    if oid == [1, 3, 6, 1, 2, 1, 1, 3, 0] {
        content.extend_from_slice(&encode_unsigned(0x43, 360_000));
    } else if let Some(value) = value {
        content.extend_from_slice(&wrap(0x04, value.as_bytes()));
    } else {
        content.extend_from_slice(&wrap(0x05, &[]));
    }
    Ok(wrap(0x30, &content))
}

fn build_response(
    request: &SnmpRequest,
    values: &BTreeMap<Vec<u32>, String>,
) -> anyhow::Result<Vec<u8>> {
    let mut encoded_varbinds = Vec::new();
    match request.pdu_tag {
        0xa0 => {
            for oid in &request.oids {
                encoded_varbinds
                    .extend_from_slice(&encode_varbind(oid, values.get(oid).map(String::as_str))?);
            }
        }
        0xa1 => {
            for oid in &request.oids {
                if let Some((next_oid, value)) = next_value(values, oid) {
                    encoded_varbinds.extend_from_slice(&encode_varbind(next_oid, Some(value))?);
                } else {
                    encoded_varbinds.extend_from_slice(&encode_varbind(oid, None)?);
                }
            }
        }
        0xa5 => {
            let mut cursor = request.oids[0].clone();
            for _ in 0..request.max_repetitions.max(1) {
                let Some((next_oid, value)) = next_value(values, &cursor) else {
                    break;
                };
                encoded_varbinds.extend_from_slice(&encode_varbind(next_oid, Some(value))?);
                cursor = next_oid.clone();
            }
        }
        _ => unreachable!("request PDU is validated"),
    }
    let mut pdu = encode_integer(request.request_id);
    pdu.extend_from_slice(&encode_integer(0));
    pdu.extend_from_slice(&encode_integer(0));
    pdu.extend_from_slice(&wrap(0x30, &encoded_varbinds));

    let mut message = encode_integer(request.version);
    message.extend_from_slice(&wrap(0x04, &request.community));
    message.extend_from_slice(&wrap(0xa2, &pdu));
    Ok(wrap(0x30, &message))
}

#[allow(clippy::too_many_arguments)]
pub async fn start_snmp_simulation(
    rule_id: String,
    rule_name: Option<String>,
    endpoint_id: String,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimSnmpConfig,
    socket: UdpSocket,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let runtime = Runtime {
        rule_id,
        callback_url,
        node_id,
        endpoint_id,
        port,
        community: config
            .community
            .clone()
            .unwrap_or_else(|| "public".to_string()),
        values: build_values(&config)?,
    };
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "SNMP simulation started");
    let mut buffer = [0_u8; MAX_SNMP_MESSAGE_SIZE];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = received.context("failed to receive SNMP request")?;
                match parse_request(&buffer[..size]) {
                    Ok(request) => {
                        let allowed = request.community == runtime.community.as_bytes();
                        if allowed {
                            let response = build_response(&request, &runtime.values)?;
                            socket.send_to(&response, peer).await.context("failed to send SNMP response")?;
                        }
                        report_request(&runtime, peer, &request, allowed);
                    }
                    Err(error) => tracing::debug!(%peer, %error, "ignored malformed SNMP request"),
                }
            }
            _ = &mut shutdown_rx => return Ok(()),
        }
    }
}

fn report_request(runtime: &Runtime, peer: SocketAddr, request: &SnmpRequest, allowed: bool) {
    let operation = match request.pdu_tag {
        0xa0 => "GET",
        0xa1 => "GETNEXT",
        0xa5 => "GETBULK",
        _ => "UNKNOWN",
    };
    report_sim_log_for_endpoint_async(
        runtime.callback_url.clone(),
        SimLogDraft {
            rule_id: runtime.rule_id.clone(),
            node_id: runtime.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: runtime.port,
            event_type: "snmp_query".to_string(),
            detail_summary: format!(
                "SNMPv{} {operation} probe {}",
                request.version + 1,
                if allowed { "accepted" } else { "rejected" }
            ),
            payload_hex: None,
        },
        runtime.endpoint_id.clone(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_request(community: &str, oid: &[u32]) -> Vec<u8> {
        let mut varbind = encode_oid(oid).unwrap();
        varbind.extend_from_slice(&wrap(0x05, &[]));
        let varbinds = wrap(0x30, &wrap(0x30, &varbind));
        let mut pdu = encode_integer(1234);
        pdu.extend_from_slice(&encode_integer(0));
        pdu.extend_from_slice(&encode_integer(0));
        pdu.extend_from_slice(&varbinds);
        let mut message = encode_integer(0);
        message.extend_from_slice(&wrap(0x04, community.as_bytes()));
        message.extend_from_slice(&wrap(0xa0, &pdu));
        wrap(0x30, &message)
    }

    #[test]
    fn parses_v1_get_and_echoes_request_id() {
        let oid = [1, 3, 6, 1, 2, 1, 1, 5, 0];
        let request = parse_request(&get_request("public", &oid)).unwrap();
        assert_eq!(request.version, 0);
        assert_eq!(request.request_id, 1234);
        assert_eq!(request.oids, [oid.to_vec()]);
        let values = build_values(&SimSnmpConfig::default()).unwrap();
        let response = build_response(&request, &values).unwrap();
        assert!(
            response
                .windows(b"snmp-veydeck".len())
                .any(|window| window == b"snmp-veydeck")
        );
    }

    #[test]
    fn rejects_indefinite_ber_lengths() {
        assert!(parse_request(&[0x30, 0x80, 0, 0]).is_err());
    }
}
