mod mysql;
mod postgresql;

pub use mysql::start_mysql_simulation;
pub use postgresql::start_postgresql_simulation;

use super::common::{SimLogDraft, encode_hex, report_sim_log_async};
use super::config::SimDatabaseConfig;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

pub(super) struct DatabaseContext {
    rule_id: String,
    callback_url: String,
    node_id: String,
    port: u16,
    pub(super) config: SimDatabaseConfig,
}

pub(super) fn report(
    context: &DatabaseContext,
    peer: SocketAddr,
    event_type: &str,
    summary: impl Into<String>,
    payload: &[u8],
) {
    report_sim_log_async(
        context.callback_url.clone(),
        SimLogDraft {
            rule_id: context.rule_id.clone(),
            node_id: context.node_id.clone(),
            client_ip: peer.ip().to_string(),
            client_port: peer.port(),
            server_port: context.port,
            event_type: event_type.to_string(),
            detail_summary: summary.into(),
            payload_hex: (!payload.is_empty())
                .then(|| encode_hex(&payload[..payload.len().min(512)])),
        },
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_database_simulation<Handler, HandlerFuture>(
    protocol: &'static str,
    rule_id: String,
    rule_name: Option<String>,
    port: u16,
    callback_url: String,
    node_id: String,
    config: SimDatabaseConfig,
    listener: TcpListener,
    mut shutdown_rx: oneshot::Receiver<()>,
    handler: Handler,
) -> anyhow::Result<()>
where
    Handler:
        Fn(Arc<DatabaseContext>, TcpStream, SocketAddr) -> HandlerFuture + Clone + Send + 'static,
    HandlerFuture: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tracing::info!(
        protocol,
        rule = %rule_name.unwrap_or_default(),
        port,
        "database simulation started"
    );
    let context = Arc::new(DatabaseContext {
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
                let context = Arc::clone(&context);
                let handler = handler.clone();
                tokio::spawn(async move {
                    if let Err(error) = handler(context, stream, peer).await {
                        tracing::debug!(protocol, %peer, %error, "database connection ended with error");
                    }
                });
            }
            _ = &mut shutdown_rx => break,
        }
    }
    Ok(())
}
