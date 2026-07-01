mod api;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use edge_core::{EdgeConfig, OciAuthMode};
use edge_store::SqliteStore;
use ipnet::Ipv4Net;
use serde::Deserialize;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "edge-agent", about = "Edge router control plane API")]
struct Cli {
    #[arg(
        long,
        env = "EDGE_DB",
        default_value = "/var/lib/edge-router/state.sqlite"
    )]
    db: PathBuf,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, default_value = "127.0.0.1:8443")]
    bind: SocketAddr,

    #[arg(long)]
    unix_socket: Option<PathBuf>,

    #[arg(long, env = "EDGE_API_TOKEN")]
    api_token: Option<String>,

    #[arg(long)]
    allow_no_auth: bool,

    #[arg(long, default_value = "ens3")]
    wan_interface: String,

    #[arg(long, default_value = "wt0")]
    netbird_interface: String,

    #[arg(long = "target-cidr", default_value = "192.168.0.0/16")]
    target_cidrs: Vec<Ipv4Net>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    reject_public_bind(cli.bind)?;

    let config_is_authoritative = cli.config.is_some();
    let requested_config = load_config(
        cli.config.as_deref(),
        cli.wan_interface,
        cli.netbird_interface,
        cli.target_cidrs,
    )?;
    let store = SqliteStore::connect(&cli.db)
        .await
        .with_context(|| format!("open state database {}", cli.db.display()))?;
    let mut config = store
        .resolve_edge_config(requested_config, config_is_authoritative)
        .await?;
    if config.api_token.is_none() {
        config.api_token = cli.api_token;
    }
    if config.api_token.is_none() && !cli.allow_no_auth {
        anyhow::bail!("missing API token; set EDGE_API_TOKEN, config api_token, or pass --allow-no-auth for local development");
    }

    let app = api::router(store, config).layer(TraceLayer::new_for_http());
    if let Some(socket) = cli.unix_socket {
        if socket.exists() {
            std::fs::remove_file(&socket)
                .with_context(|| format!("remove stale socket {}", socket.display()))?;
        }
        if let Some(parent) = socket.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create socket dir {}", parent.display()))?;
        }
        let listener = tokio::net::UnixListener::bind(&socket)
            .with_context(|| format!("bind unix socket {}", socket.display()))?;
        tracing::info!("listening on unix socket {}", socket.display());
        axum::serve(listener, app).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(cli.bind)
            .await
            .with_context(|| format!("bind {}", cli.bind))?;
        tracing::info!("listening on {}", cli.bind);
        axum::serve(listener, app).await?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    wan_interface: Option<String>,
    netbird_interface: Option<String>,
    target_cidrs: Option<Vec<Ipv4Net>>,
    oci_compartment_id: Option<String>,
    oci_vnic_id: Option<String>,
    oci_subnet_id: Option<String>,
    oci_nsg_ids: Option<Vec<String>>,
    oci_region: Option<String>,
    oci_auth: Option<OciAuthMode>,
    api_token: Option<String>,
}

fn load_config(
    path: Option<&Path>,
    wan_interface: String,
    netbird_interface: String,
    target_cidrs: Vec<Ipv4Net>,
) -> Result<EdgeConfig> {
    let mut config = EdgeConfig::new(wan_interface, netbird_interface, target_cidrs);
    let Some(path) = path else {
        return Ok(config);
    };
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let file: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
    if let Some(value) = file.wan_interface {
        config.wan_interface = value;
    }
    if let Some(value) = file.netbird_interface {
        config.netbird_interface = value;
    }
    if let Some(value) = file.target_cidrs {
        config.target_cidrs = value;
    }
    config.oci_compartment_id = file.oci_compartment_id;
    config.oci_vnic_id = file.oci_vnic_id;
    config.oci_subnet_id = file.oci_subnet_id;
    config.oci_nsg_ids = file.oci_nsg_ids.unwrap_or_default();
    config.oci_region = file.oci_region;
    if let Some(value) = file.oci_auth {
        config.oci_auth = value;
    }
    config.api_token = file.api_token;
    Ok(config)
}

fn reject_public_bind(addr: SocketAddr) -> Result<()> {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            anyhow::bail!("refusing to bind management API to public wildcard address {addr}")
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            anyhow::bail!("refusing to bind management API to public wildcard address {addr}")
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_wildcard_bind() {
        let addr: SocketAddr = "0.0.0.0:8443".parse().unwrap();

        assert!(reject_public_bind(addr).is_err());
    }
}
