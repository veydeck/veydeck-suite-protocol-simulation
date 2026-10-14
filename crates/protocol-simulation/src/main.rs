use anyhow::Context;
use protocol_simulation as api;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "protocol_simulation=info,tower_http=info".to_string()),
        )
        .init();

    let config = api::Config::from_env();
    let state = api::AppState::initialize(config.clone()).await?;
    let router = api::router(state);
    let addr: SocketAddr = format!("0.0.0.0:{}", config.http_port)
        .parse()
        .context("invalid HTTP bind address")?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("protocol simulation listening on {}", addr);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            return;
        };
        signal.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
