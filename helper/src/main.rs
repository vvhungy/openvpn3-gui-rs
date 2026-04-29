mod nft;
mod service;
mod watcher;

use anyhow::{Context, Result};
use service::KillSwitch;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

const BUS_NAME: &str = "net.openvpn.v3.killswitch";
const OBJECT_PATH: &str = "/net/openvpn/v3/killswitch";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("openvpn3-killswitch-helper starting");

    let _conn = zbus::connection::Builder::system()
        .context("connect to system bus")?
        .name(BUS_NAME)
        .context("claim bus name")?
        .serve_at(OBJECT_PATH, KillSwitch::default())
        .context("register service")?
        .build()
        .await
        .context("build connection")?;

    info!(bus = BUS_NAME, path = OBJECT_PATH, "service registered");

    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    tokio::select! {
        _ = sigterm.recv() => info!("SIGTERM received"),
        _ = sigint.recv()  => info!("SIGINT received"),
    }

    info!("shutting down — clearing any active rules");
    service::cleanup_rules().await;
    Ok(())
}
