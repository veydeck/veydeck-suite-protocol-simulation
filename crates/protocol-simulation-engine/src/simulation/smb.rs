use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimSmbConfig;
use super::wire::{read_netbios, tlv};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config: SimSmbConfig,
}

const NTLM_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;

fn u16_at(bytes: &[u8], offset: usize) -> anyhow::Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(|| anyhow::anyhow!("truncated SMB field"))?
            .try_into()?,
    ))
}

fn header(request: &[u8], command: u16, status: u32, session: u64) -> Vec<u8> {
    let mut out = vec![0; 64];
    out[..4].copy_from_slice(b"\xfeSMB");
    out[4..6].copy_from_slice(&64_u16.to_le_bytes());
    out[8..12].copy_from_slice(&status.to_le_bytes());
    out[12..14].copy_from_slice(&command.to_le_bytes());
    out[14..16].copy_from_slice(&1_u16.to_le_bytes());
    out[16..20].copy_from_slice(&1_u32.to_le_bytes());
    if request.starts_with(b"\xfeSMB") {
        out[24..40].copy_from_slice(&request[24..40]);
    }
    out[40..48].copy_from_slice(&session.to_le_bytes());
    out
}

fn error(request: &[u8], command: u16, status: u32) -> Vec<u8> {
    [
        header(request, command, status, 0),
        vec![9, 0, 0, 0, 0, 0, 0, 0, 0],
    ]
    .concat()
}

fn negotiate(request: &[u8]) -> anyhow::Result<Vec<u8>> {
    let dialect = if request.starts_with(b"\xffSMB") {
        anyhow::ensure!(
            request.get(4) == Some(&0x72) && request.windows(9).any(|s| s == b"SMB 2.002"),
            "SMB1 is unsupported; SMB2 upgrade required"
        );
        0x0202_u16
    } else {
        anyhow::ensure!(
            u16_at(request, 64)? == 36,
            "invalid SMB2 negotiate structure"
        );
        let count = usize::from(u16_at(request, 66)?);
        anyhow::ensure!(
            count > 0 && request.len() >= 100 + count * 2,
            "truncated dialect list"
        );
        let offered = &request[100..100 + count * 2];
        [0x0210_u16, 0x0202]
            .into_iter()
            .find(|d| offered.chunks_exact(2).any(|v| v == d.to_le_bytes()))
            .unwrap_or(0)
    };
    if dialect == 0 {
        return Ok(error(request, 0, 0xc000_00bb));
    }
    // GSS-API SPNEGO NegTokenInit advertises NTLM without claiming Kerberos.
    let token = tlv(
        0x60,
        &[
            tlv(6, &[0x2b, 6, 1, 5, 5, 2]),
            tlv(0xa0, &tlv(0x30, &tlv(0xa0, &tlv(0x30, &tlv(6, NTLM_OID))))),
        ]
        .concat(),
    );
    let mut body = vec![0; 64];
    body[0..2].copy_from_slice(&65_u16.to_le_bytes());
    body[2..4].copy_from_slice(&1_u16.to_le_bytes());
    body[4..6].copy_from_slice(&dialect.to_le_bytes());
    body[8..24].copy_from_slice(b"VeydeckSMB2Sim01");
    for offset in [28, 32, 36] {
        body[offset..offset + 4].copy_from_slice(&65536_u32.to_le_bytes());
    }
    let now = ((chrono::Utc::now().timestamp() as u64) + 11_644_473_600) * 10_000_000;
    body[40..48].copy_from_slice(&now.to_le_bytes());
    body[56..58].copy_from_slice(&128_u16.to_le_bytes());
    body[58..60].copy_from_slice(&(token.len() as u16).to_le_bytes());
    Ok([header(request, 0, 0, 0), body, token].concat())
}

fn utf16(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn security_buffer(length: usize, offset: usize) -> Vec<u8> {
    [
        (length as u16).to_le_bytes().to_vec(),
        (length as u16).to_le_bytes().to_vec(),
        (offset as u32).to_le_bytes().to_vec(),
    ]
    .concat()
}

fn ntlm_challenge(config: &SimSmbConfig) -> Vec<u8> {
    let server = utf16(config.server_name.as_deref().unwrap_or("Veydeck"));
    let domain = utf16(config.domain.as_deref().unwrap_or("LAB"));
    let mut info = Vec::new();
    for (id, value) in [(1_u16, &server), (2, &domain), (3, &server), (4, &domain)] {
        info.extend_from_slice(&id.to_le_bytes());
        info.extend_from_slice(&(value.len() as u16).to_le_bytes());
        info.extend_from_slice(value);
    }
    info.extend_from_slice(&[0; 4]);
    let mut out = b"NTLMSSP\0".to_vec();
    out.extend_from_slice(&2_u32.to_le_bytes());
    out.extend_from_slice(&security_buffer(server.len(), 48));
    out.extend_from_slice(&0x008a_0205_u32.to_le_bytes());
    out.extend_from_slice(&uuid::Uuid::now_v7().as_bytes()[8..]);
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&security_buffer(info.len(), 48 + server.len()));
    out.extend_from_slice(&server);
    out.extend_from_slice(&info);
    out
}

fn session_setup(config: &SimSmbConfig, request: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        u16_at(request, 64)? == 25,
        "invalid SMB2 session setup structure"
    );
    let offset = usize::from(u16_at(request, 76)?);
    let length = usize::from(u16_at(request, 78)?);
    anyhow::ensure!(offset >= 88, "invalid SMB security buffer offset");
    let security = request
        .get(offset..offset + length)
        .ok_or_else(|| anyhow::anyhow!("truncated SMB security buffer"))?;
    let ntlm = security
        .windows(8)
        .position(|v| v == b"NTLMSSP\0")
        .and_then(|offset| security.get(offset..));
    if !ntlm.is_some_and(|value| value.len() >= 16 && value[8..12] == 1_u32.to_le_bytes()) {
        return Ok(error(request, 1, STATUS_ACCESS_DENIED));
    }
    let token = tlv(
        0xa1,
        &tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(10, &[1])),
                tlv(0xa1, &tlv(6, NTLM_OID)),
                tlv(0xa2, &tlv(4, &ntlm_challenge(config))),
            ]
            .concat(),
        ),
    );
    let mut body = vec![9, 0, 0, 0, 72, 0];
    body.extend_from_slice(&(token.len() as u16).to_le_bytes());
    Ok([header(request, 1, 0xc000_0016, 1), body, token].concat())
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    let mut negotiated = false;
    while let Some(request) = read_netbios(&mut stream).await? {
        let command = if request.starts_with(b"\xffSMB") {
            0
        } else {
            anyhow::ensure!(
                request.len() >= 64
                    && request.starts_with(b"\xfeSMB")
                    && u16_at(&request, 4)? == 64,
                "invalid SMB2 header"
            );
            anyhow::ensure!(
                request[20..24] == [0; 4],
                "compound SMB2 requests are unsupported"
            );
            u16_at(&request, 12)?
        };
        let reply = match command {
            0 => {
                let reply = negotiate(&request)?;
                negotiated = reply[8..12] == [0; 4];
                reply
            }
            1 if negotiated => session_setup(&ctx.config, &request)?,
            _ => error(&request, command, STATUS_ACCESS_DENIED),
        };
        report_sim_log_async(
            ctx.callback_url.clone(),
            SimLogDraft {
                rule_id: ctx.rule_id.clone(),
                node_id: ctx.node_id.clone(),
                client_ip: peer.ip().to_string(),
                client_port: peer.port(),
                server_port: ctx.port,
                event_type: "connection".into(),
                detail_summary: format!("SMB2 discovery command {command}"),
                payload_hex: Some(encode_hex(&request[..request.len().min(512)])),
            },
        );
        let length = (reply.len() as u32).to_be_bytes();
        let frame = [&length[..], &reply].concat();
        tokio::time::timeout(super::wire::IDLE_TIMEOUT, stream.write_all(&frame)).await??;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiate_selects_offered_dialect_and_preserves_message_id() {
        let mut request = header(&[], 0, 0, 0);
        request[24..32].copy_from_slice(&42_u64.to_le_bytes());
        let mut body = vec![0; 36];
        body[..2].copy_from_slice(&36_u16.to_le_bytes());
        body[2..4].copy_from_slice(&1_u16.to_le_bytes());
        request.extend(body);
        request.extend(0x0210_u16.to_le_bytes());
        let reply = negotiate(&request).unwrap();
        assert_eq!(u16_at(&reply, 68).unwrap(), 0x0210);
        assert_eq!(&reply[24..32], &42_u64.to_le_bytes());
        assert_eq!(u16_at(&reply, 120).unwrap(), 128);
        assert!(negotiate(&request[..100]).is_err());
    }
    #[test]
    fn ntlm_challenge_contains_configured_utf16_identity_and_valid_offsets() {
        let config = SimSmbConfig {
            server_name: Some("HOST".into()),
            domain: Some("DOMAIN".into()),
        };
        let challenge = ntlm_challenge(&config);
        assert_eq!(&challenge[..12], b"NTLMSSP\0\x02\0\0\0");
        let name_offset = u32::from_le_bytes(challenge[16..20].try_into().unwrap()) as usize;
        assert_eq!(&challenge[name_offset..name_offset + 8], utf16("HOST"));
        let info_offset = u32::from_le_bytes(challenge[44..48].try_into().unwrap()) as usize;
        assert!(
            challenge[info_offset..]
                .windows(12)
                .any(|v| v == utf16("DOMAIN"))
        );
    }
    #[test]
    fn session_setup_rejects_out_of_bounds_security_buffer() {
        let mut request = header(&[], 1, 0, 0);
        request.extend([0; 24]);
        request[64..66].copy_from_slice(&25_u16.to_le_bytes());
        request[76..78].copy_from_slice(&65535_u16.to_le_bytes());
        request[78..80].copy_from_slice(&1_u16.to_le_bytes());
        assert!(session_setup(&SimSmbConfig::default(), &request).is_err());
    }
}
