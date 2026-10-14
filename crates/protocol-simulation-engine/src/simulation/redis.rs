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

fn parse_redis_command(input: &[u8]) -> Option<RedisCommand> {
    let text = std::str::from_utf8(input)
        .ok()?
        .trim_matches(|ch| ch == '\r' || ch == '\n');
    if text.is_empty() {
        return None;
    }

    if !text.starts_with('*') {
        let mut parts = text.split_whitespace();
        let name = parts.next()?.to_ascii_uppercase();
        let args = parts.map(ToString::to_string).collect();
        return Some(RedisCommand { name, args });
    }

    let mut lines = text.lines().map(str::trim_end);
    let array_len = lines.next()?.strip_prefix('*')?.parse::<usize>().ok()?;
    let mut values = Vec::with_capacity(array_len);

    for _ in 0..array_len {
        let bulk_header = lines.next()?;
        if !bulk_header.starts_with('$') {
            return None;
        }
        let value = lines.next()?.to_string();
        values.push(value);
    }

    let name = values.first()?.to_ascii_uppercase();
    let args = values.into_iter().skip(1).collect();
    Some(RedisCommand { name, args })
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
    let mut lines = vec![
        "# Server".to_string(),
        "redis_version:6.2.14".to_string(),
        "redis_git_sha1:00000000".to_string(),
        "redis_mode:standalone".to_string(),
        "os:Linux x86_64".to_string(),
        "tcp_port:6379".to_string(),
        "# Clients".to_string(),
        "connected_clients:1".to_string(),
        "# Memory".to_string(),
        "used_memory_human:12.34M".to_string(),
    ];

    if let Some(server_info) = &config.server_info {
        for (key, value) in server_info {
            lines.push(format!("{}:{}", key, value));
        }
    }

    lines.join("\r\n")
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
    if let Some((response, event_type)) = redis_custom_response(config, command) {
        return (response, event_type);
    }

    let require_auth = config.require_auth.unwrap_or(false);
    if require_auth && !*authed && !matches!(command.name.as_str(), "AUTH" | "PING") {
        return (
            redis_error("NOAUTH Authentication required."),
            "redis_command".to_string(),
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

    if let Some(banner) = &ctx.config.banner {
        stream.write_all(&redis_simple(banner)).await?;
    }

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
    loop {
        let read_len = stream.read(&mut buffer).await?;
        if read_len == 0 {
            break;
        }

        let payload = &buffer[..read_len];
        let Some(command) = parse_redis_command(payload) else {
            stream
                .write_all(&redis_error("ERR Protocol error: invalid request"))
                .await?;
            continue;
        };

        let (response, event_type) = redis_response_for_command(&ctx.config, &command, &mut authed);
        let summary = if command.args.is_empty() {
            format!("Redis command: {}", command.name)
        } else {
            format!("Redis command: {} {}", command.name, command.args.join(" "))
        };
        let payload_hex = Some(super::common::encode_hex(
            &payload[..payload.len().min(512)],
        ));

        let draft = SimLogDraft {
            rule_id: ctx.rule_id.clone(),
            node_id: ctx.node_id.clone(),
            client_ip: client_ip.clone(),
            client_port,
            server_port: ctx.port,
            event_type,
            detail_summary: summary,
            payload_hex,
        };
        report_sim_log_async(ctx.callback_url.clone(), draft);

        stream.write_all(&response).await?;
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
