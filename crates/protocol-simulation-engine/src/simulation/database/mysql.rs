use super::{DatabaseContext, report, run_database_simulation};
use crate::simulation::config::SimDatabaseConfig;
use anyhow::{Context, bail};
use sha1::{Digest, Sha1};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const AUTH_SEED: &[u8; 20] = b"veydeck01simulation1";
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
const SERVER_CAPABILITIES: u32 = 0x0000_0001
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH;
const MAX_PACKET_SIZE: usize = 64 * 1024;
const DEFAULT_SERVER_VERSION: &str = "8.0.36-veydeck";

struct HandshakeResponse<'a> {
    username: &'a str,
    auth_response: &'a [u8],
    database: Option<&'a str>,
}

fn packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut packet = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, sequence];
    packet.extend_from_slice(payload);
    packet
}

async fn read_packet<Stream>(stream: &mut Stream) -> anyhow::Result<Option<(u8, Vec<u8>)>>
where
    Stream: AsyncRead + Unpin,
{
    let first = match stream.read_u8().await {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let second = stream.read_u8().await?;
    let third = stream.read_u8().await?;
    let length = usize::from(first) | (usize::from(second) << 8) | (usize::from(third) << 16);
    if length > MAX_PACKET_SIZE {
        bail!("MySQL packet exceeds simulation limit: {length}");
    }
    let sequence = stream.read_u8().await?;
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(Some((sequence, payload)))
}

fn handshake(version: &str) -> Vec<u8> {
    let mut payload = vec![0x0a];
    payload.extend_from_slice(version.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(&AUTH_SEED[..8]);
    payload.push(0);
    payload.extend_from_slice(&(SERVER_CAPABILITIES as u16).to_le_bytes());
    payload.push(0x21);
    payload.extend_from_slice(&0x0002_u16.to_le_bytes());
    payload.extend_from_slice(&((SERVER_CAPABILITIES >> 16) as u16).to_le_bytes());
    payload.push(21);
    payload.extend_from_slice(&[0; 10]);
    payload.extend_from_slice(&AUTH_SEED[8..]);
    payload.push(0);
    payload.extend_from_slice(b"mysql_native_password\0");
    packet(0, &payload)
}

fn take_cstring<'a>(input: &'a [u8], offset: &mut usize) -> anyhow::Result<&'a str> {
    let remaining = input
        .get(*offset..)
        .context("MySQL handshake response is truncated")?;
    let length = remaining
        .iter()
        .position(|byte| *byte == 0)
        .context("MySQL handshake response contains an unterminated string")?;
    let value = std::str::from_utf8(&remaining[..length])
        .context("MySQL handshake response contains invalid UTF-8")?;
    *offset += length + 1;
    Ok(value)
}

fn read_lenenc_integer(input: &[u8], offset: &mut usize) -> anyhow::Result<usize> {
    let first = *input
        .get(*offset)
        .context("MySQL length-encoded integer is missing")?;
    *offset += 1;
    match first {
        0..=250 => Ok(usize::from(first)),
        0xfc => {
            let bytes: [u8; 2] = input
                .get(*offset..*offset + 2)
                .context("MySQL length-encoded integer is truncated")?
                .try_into()?;
            *offset += 2;
            Ok(usize::from(u16::from_le_bytes(bytes)))
        }
        _ => bail!("unsupported MySQL length-encoded integer"),
    }
}

fn parse_handshake_response(payload: &[u8]) -> anyhow::Result<HandshakeResponse<'_>> {
    if payload.len() < 32 {
        bail!("MySQL handshake response is too short");
    }
    let capabilities = u32::from_le_bytes(payload[..4].try_into()?);
    if capabilities & CLIENT_PROTOCOL_41 == 0 {
        bail!("MySQL client does not support protocol 4.1");
    }
    let mut offset = 32;
    let username = take_cstring(payload, &mut offset)?;
    let auth_length = if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        read_lenenc_integer(payload, &mut offset)?
    } else if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let length = usize::from(
            *payload
                .get(offset)
                .context("MySQL authentication response length is missing")?,
        );
        offset += 1;
        length
    } else {
        payload[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .context("MySQL authentication response is unterminated")?
    };
    let auth_response = payload
        .get(offset..offset + auth_length)
        .context("MySQL authentication response is truncated")?;
    offset += auth_length;
    let database = if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        Some(take_cstring(payload, &mut offset)?)
    } else {
        None
    };
    Ok(HandshakeResponse {
        username,
        auth_response,
        database,
    })
}

fn native_password_response(password: &str) -> [u8; 20] {
    let first = Sha1::digest(password.as_bytes());
    let second = Sha1::digest(first);
    let mut challenge = Sha1::new();
    challenge.update(AUTH_SEED);
    challenge.update(second);
    let challenge = challenge.finalize();
    let mut response = [0; 20];
    for (index, value) in response.iter_mut().enumerate() {
        *value = first[index] ^ challenge[index];
    }
    response
}

fn credentials_match(config: &SimDatabaseConfig, username: &str, auth_response: &[u8]) -> bool {
    config.credentials.as_ref().is_some_and(|credentials| {
        credentials.iter().any(|credential| {
            credential.username == username
                && native_password_response(&credential.password).as_slice() == auth_response
        })
    })
}

fn database_exists(config: &SimDatabaseConfig, database: Option<&str>) -> bool {
    database.is_none_or(|database| {
        config
            .databases
            .as_ref()
            .is_none_or(|databases| databases.iter().any(|item| item == database))
    })
}

fn ok_packet(sequence: u8) -> Vec<u8> {
    packet(sequence, &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
}

fn error_packet(sequence: u8, code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut payload = vec![0xff];
    payload.extend_from_slice(&code.to_le_bytes());
    payload.push(b'#');
    payload.extend_from_slice(sql_state.as_bytes());
    payload.extend_from_slice(message.as_bytes());
    packet(sequence, &payload)
}

fn push_lenenc_string(payload: &mut Vec<u8>, value: &str) {
    payload.push(value.len() as u8);
    payload.extend_from_slice(value.as_bytes());
}

fn column_definition(name: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    for value in ["def", "", "", "", name, ""] {
        push_lenenc_string(&mut payload, value);
    }
    payload.push(0x0c);
    payload.extend_from_slice(&0x0021_u16.to_le_bytes());
    payload.extend_from_slice(&1024_u32.to_le_bytes());
    payload.push(0xfd);
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(&[0, 0]);
    payload
}

async fn write_text_result<Stream>(
    stream: &mut Stream,
    column: &str,
    value: &str,
) -> anyhow::Result<()>
where
    Stream: AsyncWrite + Unpin,
{
    stream.write_all(&packet(1, &[1])).await?;
    stream
        .write_all(&packet(2, &column_definition(column)))
        .await?;
    stream.write_all(&packet(3, &[0xfe, 0, 0, 2, 0])).await?;
    let mut row = Vec::new();
    push_lenenc_string(&mut row, value);
    stream.write_all(&packet(4, &row)).await?;
    stream.write_all(&packet(5, &[0xfe, 0, 0, 2, 0])).await?;
    Ok(())
}

fn normalize_query(query: &str) -> String {
    query
        .trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn configured_query_response<'a>(config: &'a SimDatabaseConfig, query: &str) -> Option<&'a str> {
    let normalized = normalize_query(query);
    config.query_responses.as_ref().and_then(|responses| {
        responses.iter().find_map(|(configured, response)| {
            (normalize_query(configured) == normalized).then_some(response.as_str())
        })
    })
}

async fn serve_session<Stream, Observer>(
    config: &SimDatabaseConfig,
    stream: &mut Stream,
    mut observe: Observer,
) -> anyhow::Result<()>
where
    Stream: AsyncRead + AsyncWrite + Unpin,
    Observer: FnMut(&str, String, &[u8]),
{
    let server_version = config
        .server_version
        .as_deref()
        .unwrap_or(DEFAULT_SERVER_VERSION);
    stream.write_all(&handshake(server_version)).await?;
    let Some((_, response_payload)) = read_packet(stream).await? else {
        return Ok(());
    };
    observe(
        "auth_attempt",
        "MySQL authentication packet received".to_string(),
        &response_payload,
    );
    let response = parse_handshake_response(&response_payload)?;
    if !credentials_match(config, response.username, response.auth_response) {
        stream
            .write_all(&error_packet(
                2,
                1045,
                "28000",
                "Access denied by Veydeck simulation",
            ))
            .await?;
        return Ok(());
    }
    if !database_exists(config, response.database) {
        stream
            .write_all(&error_packet(2, 1049, "42000", "Unknown database"))
            .await?;
        return Ok(());
    }
    stream.write_all(&ok_packet(2)).await?;

    while let Some((_, command)) = read_packet(stream).await? {
        let Some((&command_code, body)) = command.split_first() else {
            continue;
        };
        match command_code {
            0x01 => break,
            0x0e => stream.write_all(&ok_packet(1)).await?,
            0x03 => {
                let query =
                    std::str::from_utf8(body).context("MySQL query contains invalid UTF-8")?;
                observe("query", format!("MySQL query received: {query}"), body);
                if normalize_query(query) == "select version()" {
                    write_text_result(stream, "VERSION()", server_version).await?;
                } else if let Some(response) = configured_query_response(config, query) {
                    write_text_result(stream, "result", response).await?;
                } else {
                    stream
                        .write_all(&error_packet(
                            1,
                            1235,
                            "42000",
                            "Query is not supported by Veydeck simulation",
                        ))
                        .await?;
                }
            }
            _ => {
                stream
                    .write_all(&error_packet(
                        1,
                        1047,
                        "08S01",
                        "Command is not supported by Veydeck simulation",
                    ))
                    .await?;
            }
        }
    }
    Ok(())
}

async fn handle(
    context: Arc<DatabaseContext>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    report(&context, peer, "connection", "MySQL client connected", &[]);
    serve_session(
        &context.config,
        &mut stream,
        |event_type, summary, payload| {
            report(&context, peer, event_type, summary, payload);
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn start_mysql_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimDatabaseConfig,
    listener: TcpListener,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    run_database_simulation(
        "mysql",
        rule_id,
        rule_name,
        port,
        callback_url,
        node_id,
        config,
        listener,
        shutdown_rx,
        handle,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{native_password_response, packet, read_packet, serve_session};
    use protocol_simulation_common::{Credential, SimDatabaseConfig};
    use tokio::io::AsyncWriteExt;

    fn config() -> SimDatabaseConfig {
        SimDatabaseConfig {
            server_version: Some("8.0.36-veydeck".to_string()),
            credentials: Some(vec![Credential {
                username: "root".to_string(),
                password: "root".to_string(),
            }]),
            databases: Some(vec!["mysql".to_string()]),
            query_responses: None,
        }
    }

    fn handshake_response(password: &str) -> Vec<u8> {
        let capabilities =
            super::CLIENT_PROTOCOL_41 | super::CLIENT_SECURE_CONNECTION | super::CLIENT_PLUGIN_AUTH;
        let mut payload = Vec::new();
        payload.extend_from_slice(&capabilities.to_le_bytes());
        payload.extend_from_slice(&0_u32.to_le_bytes());
        payload.push(0x21);
        payload.extend_from_slice(&[0; 23]);
        payload.extend_from_slice(b"root\0");
        let auth = native_password_response(password);
        payload.push(auth.len() as u8);
        payload.extend_from_slice(&auth);
        payload.extend_from_slice(b"mysql_native_password\0");
        packet(1, &payload)
    }

    async fn authenticate(stream: &mut tokio::io::DuplexStream, password: &str) -> (u8, Vec<u8>) {
        let (_, handshake) = read_packet(stream).await.unwrap().unwrap();
        assert!(
            handshake
                .windows(b"8.0.36-veydeck".len())
                .any(|value| value == b"8.0.36-veydeck")
        );
        stream
            .write_all(&handshake_response(password))
            .await
            .unwrap();
        read_packet(stream).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn configured_weak_password_authenticates_successfully() {
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });

        let (sequence, response) = authenticate(&mut client, "root").await;
        assert_eq!(sequence, 2);
        assert_eq!(response.first(), Some(&0x00));

        client.write_all(&packet(0, &[0x01])).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_password_is_rejected() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });

        let (_, response) = authenticate(&mut client, "wrong").await;
        assert_eq!(response.first(), Some(&0xff));
        assert_eq!(u16::from_le_bytes(response[1..3].try_into().unwrap()), 1045);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn select_version_returns_configured_version() {
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });
        let _ = authenticate(&mut client, "root").await;
        client
            .write_all(&packet(0, b"\x03SELECT VERSION();"))
            .await
            .unwrap();

        let mut packets = Vec::new();
        for _ in 0..5 {
            packets.push(read_packet(&mut client).await.unwrap().unwrap().1);
        }
        assert!(
            packets
                .iter()
                .any(|payload| payload.ends_with(b"8.0.36-veydeck"))
        );

        client.write_all(&packet(0, &[0x01])).await.unwrap();
        server_task.await.unwrap();
    }
}
