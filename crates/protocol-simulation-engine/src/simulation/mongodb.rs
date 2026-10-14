use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimMongodbConfig;
use anyhow::Context as _;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const OP_REPLY: i32 = 1;
const OP_QUERY: i32 = 2004;
const OP_MSG: i32 = 2013;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const MAX_REQUESTS_PER_CONNECTION: usize = 16;

struct Context {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    config: SimMongodbConfig,
}

struct Request {
    request_id: i32,
    opcode: i32,
    command: String,
}

fn read_i32_le(bytes: &[u8], offset: usize) -> anyhow::Result<i32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("MongoDB message contains a truncated integer")?
        .try_into()?;
    Ok(i32::from_le_bytes(raw))
}

fn detect_command(payload: &[u8]) -> String {
    let lowered = payload
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    for command in ["serverstatus", "buildinfo", "ismaster", "hello"] {
        if lowered
            .windows(command.len())
            .any(|window| window == command.as_bytes())
        {
            return command.to_string();
        }
    }
    "unknown".to_string()
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<Option<Request>> {
    let mut header = [0_u8; 16];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = usize::try_from(read_i32_le(&header, 0)?)?;
    if !(16..=MAX_MESSAGE_SIZE).contains(&length) {
        anyhow::bail!("invalid MongoDB message length: {length}");
    }
    let mut raw = Vec::with_capacity(length);
    raw.extend_from_slice(&header);
    raw.resize(length, 0);
    stream.read_exact(&mut raw[16..]).await?;
    let opcode = read_i32_le(&raw, 12)?;
    if !matches!(opcode, OP_QUERY | OP_MSG) {
        anyhow::bail!("unsupported MongoDB opcode: {opcode}");
    }
    Ok(Some(Request {
        request_id: read_i32_le(&raw, 4)?,
        opcode,
        command: detect_command(&raw[16..]),
    }))
}

fn bson_document(build: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut bytes = vec![0_u8; 4];
    build(&mut bytes);
    bytes.push(0);
    let length = i32::try_from(bytes.len()).expect("bounded BSON document");
    bytes[0..4].copy_from_slice(&length.to_le_bytes());
    bytes
}

fn bson_key(output: &mut Vec<u8>, kind: u8, key: &str) {
    output.push(kind);
    output.extend_from_slice(key.as_bytes());
    output.push(0);
}

fn bson_string(output: &mut Vec<u8>, key: &str, value: &str) {
    bson_key(output, 0x02, key);
    let length = i32::try_from(value.len() + 1).expect("bounded BSON string");
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    output.push(0);
}

fn bson_bool(output: &mut Vec<u8>, key: &str, value: bool) {
    bson_key(output, 0x08, key);
    output.push(u8::from(value));
}

fn bson_i32(output: &mut Vec<u8>, key: &str, value: i32) {
    bson_key(output, 0x10, key);
    output.extend_from_slice(&value.to_le_bytes());
}

fn bson_i64(output: &mut Vec<u8>, key: &str, value: i64) {
    bson_key(output, 0x12, key);
    output.extend_from_slice(&value.to_le_bytes());
}

fn bson_double(output: &mut Vec<u8>, key: &str, value: f64) {
    bson_key(output, 0x01, key);
    output.extend_from_slice(&value.to_le_bytes());
}

fn bson_nested(output: &mut Vec<u8>, key: &str, document: &[u8]) {
    bson_key(output, 0x03, key);
    output.extend_from_slice(document);
}

fn response_document(command: &str, config: &SimMongodbConfig) -> Vec<u8> {
    let version = config.server_version.as_deref().unwrap_or("7.0.14-veydeck");
    let hostname = config.hostname.as_deref().unwrap_or("mongodb-veydeck");
    match command {
        "hello" | "ismaster" => bson_document(|doc| {
            bson_bool(doc, "isWritablePrimary", true);
            bson_bool(doc, "ismaster", true);
            bson_string(doc, "me", &format!("{hostname}:27017"));
            bson_i32(doc, "minWireVersion", 0);
            bson_i32(doc, "maxWireVersion", config.max_wire_version.unwrap_or(21));
            bson_i32(doc, "maxBsonObjectSize", 16_777_216);
            bson_double(doc, "ok", 1.0);
        }),
        "buildinfo" => bson_document(|doc| {
            bson_string(doc, "version", version);
            bson_string(doc, "gitVersion", "veydeck-protocol-simulation");
            bson_i32(doc, "bits", 64);
            bson_double(doc, "ok", 1.0);
        }),
        "serverstatus" => bson_document(|doc| {
            bson_string(doc, "host", hostname);
            bson_string(doc, "version", version);
            bson_string(doc, "process", "mongod");
            bson_i64(doc, "pid", 1);
            bson_i64(doc, "uptime", 3600);
            bson_i64(doc, "uptimeMillis", 3_600_000);
            let connections = bson_document(|nested| {
                bson_i32(nested, "current", 1);
                bson_i32(nested, "available", 1023);
                bson_i64(nested, "totalCreated", 1);
            });
            bson_nested(doc, "connections", &connections);
            bson_double(doc, "ok", 1.0);
        }),
        _ => bson_document(|doc| {
            bson_double(doc, "ok", 0.0);
            bson_string(doc, "errmsg", "no such command in protocol simulation");
            bson_i32(doc, "code", 59);
        }),
    }
}

fn build_response(request: &Request, config: &SimMongodbConfig) -> Vec<u8> {
    let document = response_document(&request.command, config);
    let mut body = Vec::new();
    let response_opcode = if request.opcode == OP_QUERY {
        body.extend_from_slice(&0_i32.to_le_bytes());
        body.extend_from_slice(&0_i64.to_le_bytes());
        body.extend_from_slice(&0_i32.to_le_bytes());
        body.extend_from_slice(&1_i32.to_le_bytes());
        OP_REPLY
    } else {
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.push(0);
        OP_MSG
    };
    body.extend_from_slice(&document);

    let length = i32::try_from(16 + body.len()).expect("bounded MongoDB response");
    let mut response = Vec::with_capacity(length as usize);
    response.extend_from_slice(&length.to_le_bytes());
    response.extend_from_slice(&1_i32.to_le_bytes());
    response.extend_from_slice(&request.request_id.to_le_bytes());
    response.extend_from_slice(&response_opcode.to_le_bytes());
    response.extend_from_slice(&body);
    response
}

async fn handle(ctx: Arc<Context>, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let Some(request) = read_request(&mut stream).await? else {
            return Ok(());
        };
        stream
            .write_all(&build_response(&request, &ctx.config))
            .await?;
        report_sim_log_async(
            ctx.callback_url.clone(),
            SimLogDraft {
                rule_id: ctx.rule_id.clone(),
                node_id: ctx.node_id.clone(),
                client_ip: peer.ip().to_string(),
                client_port: peer.port(),
                server_port: ctx.port,
                event_type: "mongodb_command".to_string(),
                detail_summary: format!("MongoDB {} probe", request.command),
                payload_hex: None,
            },
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_mongodb_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimMongodbConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(rule = %rule_name.unwrap_or_default(), port, "MongoDB simulation started");
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
                let (stream, peer) = accepted.context("failed to accept MongoDB connection")?;
                let ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(30), handle(ctx, stream, peer)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "MongoDB connection ended with error"),
                        Err(_) => tracing::debug!(%peer, "MongoDB connection timed out"),
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

    fn request(opcode: i32, command: &str) -> Request {
        Request {
            request_id: 42,
            opcode,
            command: command.to_string(),
        }
    }

    #[test]
    fn detects_common_probe_commands_case_insensitively() {
        assert_eq!(detect_command(b"admin.$cmd\0buildInfo\0"), "buildinfo");
        assert_eq!(detect_command(b"test.$cmd\0serverStatus\0"), "serverstatus");
    }

    #[test]
    fn legacy_reply_echoes_request_id() {
        let response = build_response(
            &request(OP_QUERY, "buildinfo"),
            &SimMongodbConfig::default(),
        );
        assert_eq!(read_i32_le(&response, 8).unwrap(), 42);
        assert_eq!(read_i32_le(&response, 12).unwrap(), OP_REPLY);
        assert!(response.windows(7).any(|window| window == b"version"));
    }

    #[test]
    fn op_msg_reply_uses_op_msg_envelope() {
        let response = build_response(&request(OP_MSG, "hello"), &SimMongodbConfig::default());
        assert_eq!(read_i32_le(&response, 12).unwrap(), OP_MSG);
        assert!(
            response
                .windows(14)
                .any(|window| window == b"maxWireVersion")
        );
    }
}
