use super::{DatabaseContext, report, run_database_simulation};
use crate::simulation::config::SimDatabaseConfig;
use anyhow::{Context, bail};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const SSL_REQUEST_CODE: [u8; 4] = [4, 210, 22, 47];
const PROTOCOL_VERSION_3: [u8; 4] = [0, 3, 0, 0];
const MAX_PACKET_SIZE: usize = 64 * 1024;
const DEFAULT_SERVER_VERSION: &str = "16.2-veydeck";

fn backend_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(body.len() + 5);
    message.push(kind);
    message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(body);
    message
}

fn authentication_request(code: u32) -> Vec<u8> {
    backend_message(b'R', &code.to_be_bytes())
}

fn parameter_status(key: &str, value: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(key.len() + value.len() + 2);
    body.extend_from_slice(key.as_bytes());
    body.push(0);
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    backend_message(b'S', &body)
}

fn error_response(code: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"SERROR\0VERROR\0C");
    body.extend_from_slice(code.as_bytes());
    body.extend_from_slice(b"\0M");
    body.extend_from_slice(message.as_bytes());
    body.extend_from_slice(b"\0\0");
    backend_message(b'E', &body)
}

fn row_description(column_name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(column_name.as_bytes());
    body.push(0);
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(&0_i16.to_be_bytes());
    body.extend_from_slice(&25_u32.to_be_bytes());
    body.extend_from_slice(&(-1_i16).to_be_bytes());
    body.extend_from_slice(&(-1_i32).to_be_bytes());
    body.extend_from_slice(&0_i16.to_be_bytes());
    backend_message(b'T', &body)
}

fn data_row(value: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.extend_from_slice(&(value.len() as u32).to_be_bytes());
    body.extend_from_slice(value.as_bytes());
    backend_message(b'D', &body)
}

fn command_complete(tag: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(tag.len() + 1);
    body.extend_from_slice(tag.as_bytes());
    body.push(0);
    backend_message(b'C', &body)
}

fn ready_for_query() -> Vec<u8> {
    backend_message(b'Z', b"I")
}

async fn read_startup_packet<Stream>(stream: &mut Stream) -> anyhow::Result<Vec<u8>>
where
    Stream: AsyncRead + Unpin,
{
    tokio::time::timeout(crate::simulation::wire::IDLE_TIMEOUT, async {
        let length = stream.read_u32().await? as usize;
        if !(8..=MAX_PACKET_SIZE).contains(&length) {
            bail!("invalid PostgreSQL startup packet length: {length}");
        }
        let mut packet = vec![0; length - 4];
        stream.read_exact(&mut packet).await?;
        Ok(packet)
    })
    .await?
}

async fn read_frontend_message<Stream>(stream: &mut Stream) -> anyhow::Result<Option<(u8, Vec<u8>)>>
where
    Stream: AsyncRead + Unpin,
{
    tokio::time::timeout(crate::simulation::wire::IDLE_TIMEOUT, async {
        let kind = match stream.read_u8().await {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let length = stream.read_u32().await? as usize;
        if !(4..=MAX_PACKET_SIZE).contains(&length) {
            bail!("invalid PostgreSQL frontend message length: {length}");
        }
        let mut body = vec![0; length - 4];
        stream.read_exact(&mut body).await?;
        Ok(Some((kind, body)))
    })
    .await?
}

fn startup_parameter<'a>(packet: &'a [u8], name: &str) -> Option<&'a str> {
    if packet.get(..4)? != PROTOCOL_VERSION_3 {
        return None;
    }
    let values = packet[4..]
        .split(|byte| *byte == 0)
        .take_while(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.chunks_exact(2).find_map(|pair| {
        (pair[0] == name.as_bytes())
            .then(|| std::str::from_utf8(pair[1]).ok())
            .flatten()
    })
}

fn cstring(body: &[u8]) -> anyhow::Result<&str> {
    let value = body.strip_suffix(&[0]).unwrap_or(body);
    std::str::from_utf8(value).context("PostgreSQL message contains invalid UTF-8")
}

fn credentials_match(config: &SimDatabaseConfig, username: &str, password: &str) -> bool {
    config.credentials.as_ref().is_some_and(|credentials| {
        credentials
            .iter()
            .any(|item| item.username == username && item.password == password)
    })
}

fn database_exists(config: &SimDatabaseConfig, database: &str) -> bool {
    config
        .databases
        .as_ref()
        .is_none_or(|databases| databases.iter().any(|item| item == database))
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

async fn write_query_result<Stream>(
    stream: &mut Stream,
    column_name: &str,
    value: &str,
    command_tag: &str,
) -> anyhow::Result<()>
where
    Stream: AsyncWrite + Unpin,
{
    let mut response = row_description(column_name);
    response.extend_from_slice(&data_row(value));
    response.extend_from_slice(&command_complete(command_tag));
    response.extend_from_slice(&ready_for_query());
    stream.write_all(&response).await?;
    Ok(())
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
    let mut startup = read_startup_packet(stream).await?;
    if startup.as_slice() == SSL_REQUEST_CODE {
        stream.write_all(b"N").await?;
        startup = read_startup_packet(stream).await?;
    }
    if startup.get(..4) != Some(PROTOCOL_VERSION_3.as_slice()) {
        let version = startup
            .get(..4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
            .unwrap_or(0);
        let diagnostic = format!(
            "unsupported frontend protocol {}.{}: server supports 3.0",
            version >> 16,
            version & 0xffff
        );
        let body = [
            b"SFATAL\0VFATAL\0C0A000\0M".as_slice(),
            diagnostic.as_bytes(),
            b"\0\0",
        ]
        .concat();
        stream.write_all(&backend_message(b'E', &body)).await?;
        return Ok(());
    }
    observe(
        "auth_attempt",
        "PostgreSQL startup packet received".to_string(),
        &startup,
    );
    let username = startup_parameter(&startup, "user").unwrap_or_default();
    let database = startup_parameter(&startup, "database").unwrap_or(username);
    stream.write_all(&authentication_request(3)).await?;

    let Some((kind, password_body)) = read_frontend_message(stream).await? else {
        return Ok(());
    };
    if kind != b'p' {
        stream
            .write_all(&error_response("08P01", "password message expected"))
            .await?;
        return Ok(());
    }
    observe(
        "auth_attempt",
        format!("PostgreSQL password received for user {username}"),
        &password_body,
    );
    let password = cstring(&password_body)?;
    if !credentials_match(config, username, password) {
        stream
            .write_all(&error_response("28P01", "password authentication failed"))
            .await?;
        return Ok(());
    }
    if !database_exists(config, database) {
        stream
            .write_all(&error_response(
                "3D000",
                &format!("database \"{database}\" does not exist"),
            ))
            .await?;
        return Ok(());
    }

    let server_version = config
        .server_version
        .as_deref()
        .unwrap_or(DEFAULT_SERVER_VERSION);
    let mut authentication = authentication_request(0);
    authentication.extend_from_slice(&parameter_status("server_version", server_version));
    authentication.extend_from_slice(&parameter_status("server_encoding", "UTF8"));
    authentication.extend_from_slice(&parameter_status("client_encoding", "UTF8"));
    authentication.extend_from_slice(&parameter_status("DateStyle", "ISO, MDY"));
    let mut backend_key = Vec::with_capacity(8);
    backend_key.extend_from_slice(&1_u32.to_be_bytes());
    backend_key.extend_from_slice(&0x5345_434c_u32.to_be_bytes());
    authentication.extend_from_slice(&backend_message(b'K', &backend_key));
    authentication.extend_from_slice(&ready_for_query());
    stream.write_all(&authentication).await?;

    while let Some((kind, body)) = read_frontend_message(stream).await? {
        match kind {
            b'X' => break,
            b'Q' => {
                let query = cstring(&body)?;
                observe(
                    "query",
                    format!("PostgreSQL query received: {query}"),
                    &body,
                );
                match normalize_query(query).as_str() {
                    "show server_version" => {
                        write_query_result(stream, "server_version", server_version, "SHOW")
                            .await?;
                    }
                    "select version()" => {
                        let version = format!(
                            "PostgreSQL {server_version} on x86_64-pc-linux-gnu, compiled by Veydeck simulation"
                        );
                        write_query_result(stream, "version", &version, "SELECT 1").await?;
                    }
                    _ => {
                        if let Some(response) = configured_query_response(config, query) {
                            write_query_result(stream, "result", response, "SELECT 1").await?;
                        } else if query.trim().is_empty() {
                            let mut response = backend_message(b'I', &[]);
                            response.extend_from_slice(&ready_for_query());
                            stream.write_all(&response).await?;
                        } else {
                            let mut response = error_response(
                                "0A000",
                                "query is not supported by Veydeck simulation",
                            );
                            response.extend_from_slice(&ready_for_query());
                            stream.write_all(&response).await?;
                        }
                    }
                }
            }
            _ => {
                let mut response = error_response(
                    "0A000",
                    "extended query protocol is not supported by Veydeck simulation",
                );
                response.extend_from_slice(&ready_for_query());
                stream.write_all(&response).await?;
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
    report(
        &context,
        peer,
        "connection",
        "PostgreSQL client connected",
        &[],
    );
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
pub async fn start_postgresql_simulation(
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
        "postgresql",
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
    use super::{backend_message, read_frontend_message, serve_session};
    use protocol_simulation_common::{Credential, SimDatabaseConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config() -> SimDatabaseConfig {
        SimDatabaseConfig {
            server_version: Some("16.2-veydeck".to_string()),
            credentials: Some(vec![Credential {
                username: "postgres".to_string(),
                password: "postgres".to_string(),
            }]),
            databases: Some(vec!["postgres".to_string()]),
            query_responses: None,
        }
    }

    fn startup_packet() -> Vec<u8> {
        let mut body = vec![0, 3, 0, 0];
        body.extend_from_slice(b"user\0postgres\0database\0postgres\0\0");
        let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        packet.extend_from_slice(&body);
        packet
    }

    async fn read_until_ready(stream: &mut tokio::io::DuplexStream) -> Vec<(u8, Vec<u8>)> {
        let mut messages = Vec::new();
        loop {
            let message = read_frontend_message(stream).await.unwrap().unwrap();
            let ready = message.0 == b'Z';
            messages.push(message);
            if ready {
                return messages;
            }
        }
    }

    async fn authenticate(stream: &mut tokio::io::DuplexStream) -> Vec<(u8, Vec<u8>)> {
        stream.write_all(&startup_packet()).await.unwrap();
        let (kind, body) = read_frontend_message(stream).await.unwrap().unwrap();
        assert_eq!(kind, b'R');
        assert_eq!(body, 3_u32.to_be_bytes());
        stream
            .write_all(&backend_message(b'p', b"postgres\0"))
            .await
            .unwrap();
        read_until_ready(stream).await
    }

    #[tokio::test]
    async fn successful_authentication_exposes_configured_server_version() {
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });

        let messages = authenticate(&mut client).await;
        let version = messages.iter().find_map(|(kind, body)| {
            (*kind == b'S' && body.starts_with(b"server_version\0"))
                .then(|| &body[b"server_version\0".len()..body.len() - 1])
        });
        assert_eq!(version, Some(b"16.2-veydeck".as_slice()));

        client.write_all(&backend_message(b'X', &[])).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn version_queries_return_configured_server_version() {
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });
        authenticate(&mut client).await;

        client
            .write_all(&backend_message(b'Q', b"SHOW server_version;\0"))
            .await
            .unwrap();
        let messages = read_until_ready(&mut client).await;
        let row = messages
            .iter()
            .find(|(kind, _)| *kind == b'D')
            .map(|(_, body)| body)
            .unwrap();
        let value_length = u32::from_be_bytes(row[2..6].try_into().unwrap()) as usize;
        assert_eq!(&row[6..6 + value_length], b"16.2-veydeck");

        client
            .write_all(&backend_message(b'Q', b"SELECT version();\0"))
            .await
            .unwrap();
        let messages = read_until_ready(&mut client).await;
        let row = messages
            .iter()
            .find(|(kind, _)| *kind == b'D')
            .map(|(_, body)| body)
            .unwrap();
        let value_length = u32::from_be_bytes(row[2..6].try_into().unwrap()) as usize;
        assert!(row[6..6 + value_length].starts_with(b"PostgreSQL 16.2-veydeck"));

        client.write_all(&backend_message(b'X', &[])).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_password_returns_postgresql_authentication_error() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });
        client.write_all(&startup_packet()).await.unwrap();
        let _ = read_frontend_message(&mut client).await.unwrap().unwrap();
        client
            .write_all(&backend_message(b'p', b"wrong\0"))
            .await
            .unwrap();

        let (kind, body) = read_frontend_message(&mut client).await.unwrap().unwrap();
        assert_eq!(kind, b'E');
        assert!(
            body.windows(b"28P01".len())
                .any(|window| window == b"28P01")
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn ssl_request_is_rejected_before_normal_startup_continues() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let config = config();
        let server_task = tokio::spawn(async move {
            serve_session(&config, &mut server, |_, _, _| {})
                .await
                .unwrap();
        });
        client
            .write_all(&[0, 0, 0, 8, 4, 210, 22, 47])
            .await
            .unwrap();
        assert_eq!(client.read_u8().await.unwrap(), b'N');
        client.write_all(&startup_packet()).await.unwrap();
        let (kind, body) = read_frontend_message(&mut client).await.unwrap().unwrap();
        assert_eq!(kind, b'R');
        assert_eq!(body, 3_u32.to_be_bytes());
        drop(client);
        server_task.await.unwrap();
    }
}
