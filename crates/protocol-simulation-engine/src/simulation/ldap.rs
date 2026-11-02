use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimLdapConfig;
use super::wire::{read_ber, take_tlv, tlv};
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
    config: SimLdapConfig,
}

fn message(id: &[u8], tag: u8, body: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, id), tlv(tag, body)].concat())
}

fn result(id: &[u8], tag: u8, code: u8, diagnostic: &str) -> Vec<u8> {
    message(
        id,
        tag,
        &[
            tlv(0x0a, &[code]),
            tlv(0x04, b""),
            tlv(0x04, diagnostic.as_bytes()),
        ]
        .concat(),
    )
}

fn attribute(name: &str, values: &[&str]) -> Vec<u8> {
    let values: Vec<u8> = values
        .iter()
        .flat_map(|value| tlv(0x04, value.as_bytes()))
        .collect();
    tlv(
        0x30,
        &[tlv(0x04, name.as_bytes()), tlv(0x31, &values)].concat(),
    )
}

fn response(config: &SimLdapConfig, packet: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let mut outer = packet;
    let (tag, mut body) = take_tlv(&mut outer)?;
    anyhow::ensure!(tag == 0x30 && outer.is_empty(), "invalid LDAP envelope");
    let (tag, id) = take_tlv(&mut body)?;
    anyhow::ensure!(
        tag == 0x02 && !id.is_empty() && id.len() <= 4 && id[0] & 0x80 == 0,
        "invalid LDAP message id"
    );
    let (operation, mut request) = take_tlv(&mut body)?;
    match operation {
        0x42 => Ok(None), // UnbindRequest
        0x60 => {
            let (tag, version) = take_tlv(&mut request)?;
            anyhow::ensure!(tag == 0x02, "invalid LDAP version field");
            if version != [3] {
                return Ok(Some(result(id, 0x61, 2, "Only LDAPv3 is supported")));
            }
            let (tag, name) = take_tlv(&mut request)?;
            anyhow::ensure!(tag == 0x04, "invalid bind name");
            let (tag, password) = take_tlv(&mut request)?;
            let anonymous = tag == 0x80 && name.is_empty() && password.is_empty();
            Ok(Some(result(
                id,
                0x61,
                if anonymous { 0 } else { 49 },
                if anonymous {
                    ""
                } else {
                    "Only anonymous discovery is supported"
                },
            )))
        }
        0x63 => {
            let (tag, base) = take_tlv(&mut request)?;
            anyhow::ensure!(tag == 0x04, "invalid LDAP search base");
            let (tag, scope) = take_tlv(&mut request)?;
            anyhow::ensure!(
                tag == 0x0a && scope.len() == 1 && scope[0] <= 2,
                "invalid LDAP scope"
            );
            for expected in [0x0a, 0x02, 0x02] {
                let (tag, _) = take_tlv(&mut request)?;
                anyhow::ensure!(tag == expected, "invalid LDAP search fields");
            }
            let (tag, types_only) = take_tlv(&mut request)?;
            anyhow::ensure!(
                tag == 0x01 && types_only.len() == 1,
                "invalid LDAP typesOnly"
            );
            let types_only = types_only[0] != 0;
            let (filter_tag, filter) = take_tlv(&mut request)?;
            // RootDSE discovery uses the standard (objectClass=*) presence filter.
            if filter_tag != 0x87 || !filter.eq_ignore_ascii_case(b"objectClass") {
                return Ok(Some(result(
                    id,
                    0x65,
                    53,
                    "Only the objectClass presence filter is supported",
                )));
            }
            let (tag, mut attributes) = take_tlv(&mut request)?;
            anyhow::ensure!(
                tag == 0x30 && request.is_empty(),
                "invalid LDAP attribute list"
            );
            let mut requested = Vec::new();
            while !attributes.is_empty() {
                let (tag, value) = take_tlv(&mut attributes)?;
                anyhow::ensure!(tag == 0x04, "invalid LDAP attribute");
                requested.push(std::str::from_utf8(value)?.to_ascii_lowercase());
            }
            if !base.is_empty() {
                return Ok(Some(result(id, 0x65, 32, "Only RootDSE is available")));
            }
            if scope != [0] {
                return Ok(Some(result(id, 0x65, 53, "RootDSE requires base scope")));
            }
            let all = requested.is_empty() || requested.iter().any(|v| v == "*" || v == "+");
            let vendor = config.vendor_name.as_deref().unwrap_or("OpenLDAP");
            let version = config.vendor_version.as_deref().unwrap_or("2.6.8");
            let fields = [
                ("objectClass", vec!["top"]),
                ("namingContexts", vec![config.base_dn.as_str()]),
                ("supportedLDAPVersion", vec!["3"]),
                ("vendorName", vec![vendor]),
                ("vendorVersion", vec![version]),
            ];
            let attrs: Vec<u8> = fields
                .into_iter()
                .filter(|(name, _)| all || requested.contains(&name.to_ascii_lowercase()))
                .flat_map(|(name, values)| attribute(name, if types_only { &[] } else { &values }))
                .collect();
            let entry = message(id, 0x64, &[tlv(0x04, b""), tlv(0x30, &attrs)].concat());
            Ok(Some([entry, result(id, 0x65, 0, "")].concat()))
        }
        _ => Ok(Some(result(id, 0x78, 2, "Unsupported LDAP operation"))),
    }
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    while let Some(packet) = read_ber(&mut stream).await? {
        let Some(reply) = response(&ctx.config, &packet)? else {
            break;
        };
        report_sim_log_async(
            ctx.callback_url.clone(),
            SimLogDraft {
                rule_id: ctx.rule_id.clone(),
                node_id: ctx.node_id.clone(),
                client_ip: peer.ip().to_string(),
                client_port: peer.port(),
                server_port: ctx.port,
                event_type: "query".to_string(),
                detail_summary: format!("LDAP discovery under {}", ctx.config.base_dn),
                payload_hex: Some(encode_hex(&packet[..packet.len().min(512)])),
            },
        );
        tokio::time::timeout(super::wire::IDLE_TIMEOUT, stream.write_all(&reply)).await??;
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

#[cfg(test)]
mod tests {
    use super::*;
    fn search(id: &[u8], attrs: &[&str]) -> Vec<u8> {
        let attrs: Vec<u8> = attrs.iter().flat_map(|v| tlv(4, v.as_bytes())).collect();
        message(
            id,
            0x63,
            &[
                tlv(4, b""),
                tlv(10, &[0]),
                tlv(10, &[0]),
                tlv(2, &[0]),
                tlv(2, &[0]),
                tlv(1, &[0]),
                tlv(0x87, b"objectClass"),
                tlv(0x30, &attrs),
            ]
            .concat(),
        )
    }
    #[test]
    fn rootdse_returns_configured_identity_and_preserves_multibyte_id() {
        let config = SimLdapConfig {
            base_dn: "dc=test".into(),
            vendor_name: Some("Example LDAP".into()),
            vendor_version: Some("1.2.3".into()),
        };
        let output = response(&config, &search(&[1, 0], &["+"]))
            .unwrap()
            .unwrap();
        let mut messages = output.as_slice();
        let (_, mut entry) = take_tlv(&mut messages).unwrap();
        assert_eq!(take_tlv(&mut entry).unwrap(), (2, &[1, 0][..]));
        let (tag, _) = take_tlv(&mut entry).unwrap();
        assert_eq!(tag, 0x64);
        let (_, _) = take_tlv(&mut messages).unwrap();
        assert!(messages.is_empty());
        assert!(output.windows(12).any(|v| v == b"Example LDAP"));
        assert!(output.windows(5).any(|v| v == b"1.2.3"));
    }
    #[test]
    fn rootdse_honors_attribute_selection_and_rejects_fake_operation_bytes() {
        let output = response(
            &SimLdapConfig::default(),
            &search(&[1], &["supportedLDAPVersion"]),
        )
        .unwrap()
        .unwrap();
        assert!(!output.windows(10).any(|v| v == b"vendorName"));
        assert!(response(&SimLdapConfig::default(), b"random\x60\x63").is_err());
    }
    #[test]
    fn anonymous_bind_succeeds_and_named_bind_is_rejected() {
        for (name, code) in [("", 0), ("cn=admin", 49)] {
            let request = message(
                &[1],
                0x60,
                &[tlv(2, &[3]), tlv(4, name.as_bytes()), tlv(0x80, b"")].concat(),
            );
            let output = response(&SimLdapConfig::default(), &request)
                .unwrap()
                .unwrap();
            assert!(output.windows(3).any(|v| v == [10, 1, code]));
        }
    }
}
