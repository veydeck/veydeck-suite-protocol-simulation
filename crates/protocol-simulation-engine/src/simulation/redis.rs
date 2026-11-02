//! Redis 协议仿真运行器。

use super::common::{SimLogDraft, report_sim_log_async};
use super::config::SimRedisConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::{error, info};

/// 全局共享的 Redis 仿真参数，由 TCP 连接处理器消费。
struct RedisSimulationContext {
    rule_id: String,
    node_id: String,
    callback_url: String,
    port: u16,
    config: SimRedisConfig,
}

/// Redis RESP 命令解析结果。
#[derive(Debug)]
struct RedisCommand {
    name: String,
    args: Vec<String>,
}

fn parse_redis_command(input: &[u8]) -> anyhow::Result<Option<(RedisCommand, usize)>> {
    fn line(input: &[u8], offset: &mut usize) -> Option<String> {
        let length = input
            .get(*offset..)?
            .windows(2)
            .position(|b| b == b"\r\n")?;
        let text = std::str::from_utf8(&input[*offset..*offset + length])
            .ok()?
            .to_string();
        *offset += length + 2;
        Some(text)
    }
    let mut offset = 0;
    let Some(header) = line(input, &mut offset) else {
        return Ok(None);
    };
    let mut values = Vec::new();
    if let Some(count) = header.strip_prefix('*') {
        let count: usize = count.parse()?;
        anyhow::ensure!((1..=1024).contains(&count), "invalid RESP array length");
        for _ in 0..count {
            let Some(header) = line(input, &mut offset) else {
                return Ok(None);
            };
            let length: usize = header
                .strip_prefix('$')
                .ok_or_else(|| anyhow::anyhow!("expected RESP bulk string"))?
                .parse()?;
            anyhow::ensure!(
                length <= super::wire::MAX_FRAME,
                "RESP bulk string too large"
            );
            if input.len() < offset + length + 2 {
                return Ok(None);
            }
            anyhow::ensure!(
                &input[offset + length..offset + length + 2] == b"\r\n",
                "invalid RESP terminator"
            );
            values.push(std::str::from_utf8(&input[offset..offset + length])?.to_string());
            offset += length + 2;
        }
    } else {
        values.extend(header.split_whitespace().map(str::to_string));
    }
    anyhow::ensure!(!values.is_empty(), "empty Redis command");
    let name = values.remove(0).to_ascii_uppercase();
    Ok(Some((RedisCommand { name, args: values }, offset)))
}

fn redis_simple(value: &str) -> Vec<u8> {
    format!("+{}\r\n", value).into_bytes()
}

fn redis_error(value: &str) -> Vec<u8> {
    format!("-{}\r\n", value).into_bytes()
}

fn redis_bulk(value: &str) -> Vec<u8> {
    format!("${}\r\n{}\r\n", value.len(), value).into_bytes()
}

fn redis_nil() -> Vec<u8> {
    b"$-1\r\n".to_vec()
}

fn redis_array(values: &[String]) -> Vec<u8> {
    let mut output = format!("*{}\r\n", values.len()).into_bytes();
    for value in values {
        output.extend(redis_bulk(value));
    }
    output
}

fn redis_info_payload(config: &SimRedisConfig) -> String {
    let mut fields = std::collections::BTreeMap::from([
        (
            "redis_version".to_string(),
            config
                .server_version
                .clone()
                .unwrap_or_else(|| "6.2.14".to_string()),
        ),
        ("redis_git_sha1".to_string(), "00000000".to_string()),
        ("redis_mode".to_string(), "standalone".to_string()),
        ("os".to_string(), "Linux x86_64".to_string()),
        ("tcp_port".to_string(), "6379".to_string()),
        ("connected_clients".to_string(), "1".to_string()),
        ("used_memory_human".to_string(), "12.34M".to_string()),
    ]);
    if let Some(info) = &config.server_info {
        fields.extend(info.clone());
    }
    // The dedicated version field is authoritative across identity queries.
    if let Some(version) = &config.server_version {
        fields.insert("redis_version".into(), version.clone());
    }
    let version = fields
        .remove("redis_version")
        .expect("default version is present");
    let mut lines = vec!["# Server".to_string(), format!("redis_version:{version}")];
    lines.extend(
        fields
            .into_iter()
            .map(|(key, value)| format!("{key}:{value}")),
    );
    lines.join("\r\n") + "\r\n"
}

fn redis_custom_response(
    config: &SimRedisConfig,
    command: &RedisCommand,
) -> Option<(Vec<u8>, String)> {
    let responses = config.command_responses.as_ref()?;
    let command_text = std::iter::once(command.name.as_str())
        .chain(command.args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();

    for response in responses {
        if !response.command.eq_ignore_ascii_case(&command.name) {
            continue;
        }

        let args_match = response
            .args_contains
            .as_ref()
            .map(|needles| {
                needles
                    .iter()
                    .all(|needle| command_text.contains(&needle.to_ascii_lowercase()))
            })
            .unwrap_or(true);
        if args_match {
            let event_type = response
                .event_type
                .clone()
                .unwrap_or_else(|| "redis_command".to_string());
            return Some((redis_bulk(&response.response), event_type));
        }
    }

    None
}

fn redis_response_for_command(
    config: &SimRedisConfig,
    command: &RedisCommand,
    authed: &mut bool,
) -> (Vec<u8>, String) {
    let require_auth = config.require_auth.unwrap_or(false);
    if require_auth && !*authed && command.name != "AUTH" {
        return (
            redis_error("NOAUTH Authentication required."),
            "redis_command".to_string(),
        );
    }

    if let Some((response, event_type)) = redis_custom_response(config, command) {
        return (response, event_type);
    }

    let valid_arity = match command.name.as_str() {
        "PING" | "INFO" => command.args.len() <= 1,
        "GET" | "KEYS" => command.args.len() == 1,
        "AUTH" => matches!(command.args.len(), 1 | 2),
        _ => true,
    };
    if !valid_arity {
        return (
            redis_error(&format!(
                "ERR wrong number of arguments for '{}' command",
                command.name.to_ascii_lowercase()
            )),
            "redis_command".into(),
        );
    }
    match command.name.as_str() {
        "PING" => {
            let response = command
                .args
                .first()
                .map(|arg| redis_bulk(arg))
                .unwrap_or_else(|| redis_simple("PONG"));
            (response, "redis_command".to_string())
        }
        "AUTH" => {
            if !require_auth {
                *authed = true;
                return (redis_simple("OK"), "redis_command".to_string());
            }
            let expected = config.password.as_deref().unwrap_or("redis");
            let provided = command.args.last().map(String::as_str).unwrap_or_default();
            if provided == expected {
                *authed = true;
                (redis_simple("OK"), "redis_command".to_string())
            } else {
                (
                    redis_error("ERR invalid password"),
                    "exploit_attempt".to_string(),
                )
            }
        }
        "INFO" => (
            redis_bulk(&redis_info_payload(config)),
            "redis_command".to_string(),
        ),
        "CONFIG" => (
            redis_error("ERR unknown command 'CONFIG', with args beginning with:"),
            "exploit_attempt".to_string(),
        ),
        "KEYS" => {
            let keys = config
                .keys
                .as_ref()
                .map(|items| items.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            (redis_array(&keys), "exploit_attempt".to_string())
        }
        "GET" => {
            let response = command
                .args
                .first()
                .and_then(|key| config.keys.as_ref().and_then(|items| items.get(key)))
                .map(|value| redis_bulk(value))
                .unwrap_or_else(redis_nil);
            (response, "redis_command".to_string())
        }
        "SET" => (redis_simple("OK"), "redis_command".to_string()),
        "FLUSHALL" | "FLUSHDB" | "SLAVEOF" | "REPLICAOF" | "MODULE" | "EVAL" => (
            redis_error("ERR command is disabled in this simulation"),
            "exploit_attempt".to_string(),
        ),
        _ => (
            redis_error(&format!("ERR unknown command '{}'", command.name)),
            "redis_command".to_string(),
        ),
    }
}

/// 处理单个 Redis 仿真 TCP 连接。
async fn handle_redis_connection(
    ctx: Arc<RedisSimulationContext>,
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let client_ip = peer.ip().to_string();
    let client_port = peer.port();
    let mut authed = !ctx.config.require_auth.unwrap_or(false);

    let connection_draft = SimLogDraft {
        rule_id: ctx.rule_id.clone(),
        node_id: ctx.node_id.clone(),
        client_ip: client_ip.clone(),
        client_port,
        server_port: ctx.port,
        event_type: "connection".to_string(),
        detail_summary: "Redis client connected".to_string(),
        payload_hex: None,
    };
    report_sim_log_async(ctx.callback_url.clone(), connection_draft);

    let mut buffer = vec![0_u8; 4096];
    let mut pending = Vec::new();
    loop {
        let read_len =
            tokio::time::timeout(super::wire::IDLE_TIMEOUT, stream.read(&mut buffer)).await??;
        if read_len == 0 {
            anyhow::ensure!(pending.is_empty(), "truncated Redis request");
            break;
        }
        pending.extend_from_slice(&buffer[..read_len]);
        anyhow::ensure!(
            pending.len() <= super::wire::MAX_FRAME,
            "Redis request too large"
        );
        while let Some((command, consumed)) = parse_redis_command(&pending)? {
            let (response, event_type) =
                redis_response_for_command(&ctx.config, &command, &mut authed);
            report_sim_log_async(
                ctx.callback_url.clone(),
                SimLogDraft {
                    rule_id: ctx.rule_id.clone(),
                    node_id: ctx.node_id.clone(),
                    client_ip: client_ip.clone(),
                    client_port,
                    server_port: ctx.port,
                    event_type,
                    detail_summary: format!("Redis command: {}", command.name),
                    payload_hex: Some(super::common::encode_hex(&pending[..consumed.min(512)])),
                },
            );
            stream.write_all(&response).await?;
            pending.drain(..consumed);
        }
    }

    Ok(())
}

/// 开启 Redis TCP 协议仿真。
#[allow(clippy::too_many_arguments)]
pub async fn start_redis_simulation(
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimRedisConfig,
    listener: tokio::net::TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(RedisSimulationContext {
        rule_id: rule_id.clone(),
        node_id,
        callback_url,
        port,
        config,
    });

    let name_str = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());
    info!(
        "Simulation Redis server started for rule '{}' (ID: {}) listening on port {}",
        name_str, rule_id, port
    );

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, peer) = accept_result?;
                let conn_ctx = Arc::clone(&ctx);
                tokio::spawn(async move {
                    if let Err(err) = handle_redis_connection(conn_ctx, stream, peer).await {
                        error!("Redis simulation connection error from {}: {:?}", peer, err);
                    }
                });
            }
            _ = &mut shutdown_rx => {
                info!(
                    "Simulation Redis server for rule '{}' (ID: {}) on port {} gracefully shutting down...",
                    name_str, rule_id, port
                );
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn info_has_one_authoritative_version() {
        let config = SimRedisConfig {
            server_version: Some("7.2.5".into()),
            server_info: Some(std::collections::BTreeMap::from([
                ("redis_version".into(), "6.0".into()),
                ("os".into(), "FreeBSD".into()),
            ])),
            ..Default::default()
        };
        let info = redis_info_payload(&config);
        assert_eq!(info.matches("redis_version:").count(), 1);
        assert!(info.contains("redis_version:7.2.5\r\n"));
        assert!(info.contains("os:FreeBSD\r\n"));
    }
    #[test]
    fn parses_fragmented_and_pipelined_resp_by_length() {
        let request = b"*2\r\n$4\r\nECHO\r\n$4\r\na\r\nb\r\nPING\r\n";
        assert!(parse_redis_command(&request[..20]).unwrap().is_none());
        let (command, used) = parse_redis_command(request).unwrap().unwrap();
        assert_eq!(command.args, ["a\r\nb"]);
        assert_eq!(
            parse_redis_command(&request[used..])
                .unwrap()
                .unwrap()
                .0
                .name,
            "PING"
        );
        assert!(parse_redis_command(b"*99999999\r\n").is_err());
    }
    #[test]
    fn authentication_gates_info_and_custom_responses() {
        let config = SimRedisConfig {
            require_auth: Some(true),
            password: Some("secret".into()),
            ..Default::default()
        };
        let mut authed = false;
        let command = |name: &str, args: Vec<String>| RedisCommand {
            name: name.into(),
            args,
        };
        assert!(
            redis_response_for_command(&config, &command("INFO", vec![]), &mut authed)
                .0
                .starts_with(b"-NOAUTH")
        );
        assert_eq!(
            redis_response_for_command(
                &config,
                &command("AUTH", vec!["secret".into()]),
                &mut authed
            )
            .0,
            b"+OK\r\n"
        );
        assert!(
            redis_response_for_command(&config, &command("INFO", vec![]), &mut authed)
                .0
                .starts_with(b"$")
        );
    }
    #[test]
    fn invalid_get_arity_returns_protocol_error_instead_of_nil() {
        let config = SimRedisConfig::default();
        let mut authed = true;
        let command = RedisCommand {
            name: "GET".into(),
            args: vec!["/".into(), "HTTP/1.0".into()],
        };
        assert_eq!(
            redis_response_for_command(&config, &command, &mut authed).0,
            b"-ERR wrong number of arguments for 'get' command\r\n"
        );
    }
}
