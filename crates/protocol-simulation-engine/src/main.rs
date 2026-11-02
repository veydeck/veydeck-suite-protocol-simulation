mod simulation;

use anyhow::Context;
use protocol_simulation_common::{
    BoundEndpoint, EngineLaunchConfig, ProtocolId, TransportProtocol, protocol_descriptor,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "protocol_simulation_engine=info".to_string()),
        )
        .init();

    let mut config = launch_config_from_env()?;
    config.behavior =
        protocol_simulation_common::validate_behavior(config.protocol, config.behavior)
            .context("invalid protocol behavior")?;
    if config.schema_version != 1 {
        anyhow::bail!(
            "unsupported engine launch schemaVersion: {}",
            config.schema_version
        );
    }
    let endpoints = validated_endpoints(&config)?;
    tracing::info!(
        protocol = config.protocol.as_str(),
        rule_id = config.rule_id,
        instance_id = config.instance_id,
        endpoint_count = endpoints.len(),
        "starting protocol simulation engine"
    );
    simulation::initialize_reporter(
        config.callback_url.clone(),
        config.callback_token.clone(),
        config.instance_id.clone(),
        config.endpoints.clone(),
    )?;

    let mut simulations = JoinSet::new();
    let mut shutdown_senders = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let addr: SocketAddr = format!("0.0.0.0:{}", endpoint.container_port)
            .parse()
            .context("invalid simulation bind address")?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        shutdown_senders.push(shutdown_tx);
        match endpoint.transport {
            TransportProtocol::Tcp => {
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("failed to bind TCP simulation listener on {addr}"))?;
                simulations.spawn(run_tcp_simulation(
                    config.clone(),
                    endpoint,
                    listener,
                    shutdown_rx,
                ));
            }
            TransportProtocol::Udp => {
                let socket = UdpSocket::bind(addr)
                    .await
                    .with_context(|| format!("failed to bind UDP simulation listener on {addr}"))?;
                simulations.spawn(run_udp_simulation(
                    config.clone(),
                    endpoint,
                    socket,
                    shutdown_rx,
                ));
            }
        }
    }

    tokio::select! {
        result = simulations.join_next() => {
            signal_simulations(shutdown_senders);
            match result {
                Some(result) => result.context("simulation endpoint task failed")?,
                None => Ok(()),
            }
        },
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; waiting up to 5 seconds for graceful engine shutdown");
            signal_simulations(shutdown_senders);
            match timeout(Duration::from_secs(5), drain_simulations(&mut simulations)).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!("graceful engine shutdown timed out after 5 seconds");
                    Ok(())
                }
            }
        }
    }
}

fn validated_endpoints(config: &EngineLaunchConfig) -> anyhow::Result<Vec<BoundEndpoint>> {
    if config.endpoints.is_empty() {
        anyhow::bail!("simulation launch config does not contain an endpoint");
    }
    let descriptor = protocol_descriptor(config.protocol);
    let mut seen = HashSet::new();
    for endpoint in &config.endpoints {
        if !seen.insert(endpoint.endpoint_id.as_str()) {
            anyhow::bail!("duplicate simulation endpoint: {}", endpoint.endpoint_id);
        }
        let expected = descriptor
            .endpoints
            .iter()
            .find(|candidate| candidate.id == endpoint.endpoint_id)
            .with_context(|| format!("unknown simulation endpoint: {}", endpoint.endpoint_id))?;
        if endpoint.transport != expected.transport
            || endpoint.container_port != expected.container_port
        {
            anyhow::bail!(
                "simulation endpoint {} does not match the {} protocol descriptor",
                endpoint.endpoint_id,
                config.protocol.as_str()
            );
        }
    }
    for expected in descriptor
        .endpoints
        .iter()
        .filter(|endpoint| endpoint.required)
    {
        if !seen.contains(expected.id.as_str()) {
            anyhow::bail!("required simulation endpoint is missing: {}", expected.id);
        }
    }
    Ok(config.endpoints.clone())
}

fn signal_simulations(senders: Vec<oneshot::Sender<()>>) {
    for sender in senders {
        let _ = sender.send(());
    }
}

async fn drain_simulations(simulations: &mut JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    while let Some(result) = simulations.join_next().await {
        result.context("simulation endpoint task failed")??;
    }
    Ok(())
}

async fn run_tcp_simulation(
    config: EngineLaunchConfig,
    endpoint: BoundEndpoint,
    listener: TcpListener,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    let node_id = env_string("VEYDECK_NODE_ID", "local");
    let callback_url = config.callback_url.clone();
    let rule_name = Some(config.rule_name.clone());
    let port = endpoint.container_port;
    match config.protocol {
        ProtocolId::Http => {
            simulation::start_http_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Redis => {
            simulation::start_redis_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Smtp => {
            simulation::start_smtp_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Pop3 => {
            simulation::start_pop3_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Imap => {
            simulation::start_imap_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Ssh => {
            simulation::start_ssh_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Ftp => {
            simulation::start_ftp_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Rdp => {
            simulation::start_rdp_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Telnet => {
            simulation::start_telnet_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Mysql => {
            simulation::start_mysql_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Postgresql => {
            simulation::start_postgresql_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Smb => {
            simulation::start_smb_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Ldap => {
            simulation::start_ldap_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Dns => {
            simulation::start_dns_tcp_simulation(
                config.rule_id,
                rule_name,
                endpoint.endpoint_id,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Mongodb => {
            simulation::start_mongodb_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Memcached => {
            simulation::start_memcached_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Mqtt => {
            simulation::start_mqtt_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Vnc => {
            simulation::start_vnc_simulation(
                config.rule_id,
                rule_name,
                port,
                callback_url,
                node_id,
                parse_rule_config(config.behavior)?,
                listener,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Snmp => anyhow::bail!("SNMP requires a UDP endpoint"),
    }
}

async fn run_udp_simulation(
    config: EngineLaunchConfig,
    endpoint: BoundEndpoint,
    socket: UdpSocket,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    match config.protocol {
        ProtocolId::Dns => {
            simulation::start_dns_udp_simulation(
                config.rule_id,
                Some(config.rule_name),
                endpoint.endpoint_id,
                endpoint.container_port,
                config.callback_url,
                env_string("VEYDECK_NODE_ID", "local"),
                parse_rule_config(config.behavior)?,
                socket,
                shutdown_rx,
            )
            .await
        }
        ProtocolId::Snmp => {
            simulation::start_snmp_simulation(
                config.rule_id,
                Some(config.rule_name),
                endpoint.endpoint_id,
                endpoint.container_port,
                config.callback_url,
                env_string("VEYDECK_NODE_ID", "local"),
                parse_rule_config(config.behavior)?,
                socket,
                shutdown_rx,
            )
            .await
        }
        _ => anyhow::bail!(
            "protocol {} does not support UDP endpoint {}",
            config.protocol.as_str(),
            endpoint.endpoint_id
        ),
    }
}

fn launch_config_from_env() -> anyhow::Result<EngineLaunchConfig> {
    let value = std::env::var("VEYDECK_WORKLOAD_CONFIG_JSON")
        .context("VEYDECK_WORKLOAD_CONFIG_JSON is required")?;
    serde_json::from_str(&value).context("VEYDECK_WORKLOAD_CONFIG_JSON must be a v1 launch config")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn env_string(name: &str, default_value: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default_value.to_string())
}

fn parse_rule_config<T>(value: serde_json::Value) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(value).context("failed to parse simulation rule behavior")
}
