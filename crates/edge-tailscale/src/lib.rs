use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;

pub type Result<T> = std::result::Result<T, TailscaleError>;

#[derive(Debug, Error)]
pub enum TailscaleError {
    #[error("command failed: {0}")]
    Command(String),
    #[error("tailscale JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("process failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailscaleCli {
    tailscale: PathBuf,
    ip: PathBuf,
    ping: PathBuf,
}

impl Default for TailscaleCli {
    fn default() -> Self {
        Self {
            tailscale: PathBuf::from("tailscale"),
            ip: PathBuf::from("ip"),
            ping: PathBuf::from("ping"),
        }
    }
}

impl TailscaleCli {
    pub fn new(
        tailscale: impl Into<PathBuf>,
        ip: impl Into<PathBuf>,
        ping: impl Into<PathBuf>,
    ) -> Self {
        Self {
            tailscale: tailscale.into(),
            ip: ip.into(),
            ping: ping.into(),
        }
    }

    pub async fn status(&self) -> Result<TailscaleStatus> {
        let output = run(&self.tailscale, ["status", "--json"]).await?;
        parse_status(&output.stdout)
    }

    pub async fn route_get(&self, target: Ipv4Addr) -> Result<RouteCheck> {
        let output = run_owned(
            &self.ip,
            vec!["route".to_owned(), "get".to_owned(), target.to_string()],
        )
        .await?;
        Ok(RouteCheck {
            target,
            route: output.stdout.trim().to_owned(),
            via_tailscale: output.stdout.contains("tailscale0"),
        })
    }

    pub async fn ping_once(&self, target: Ipv4Addr) -> Result<CommandOutput> {
        run_owned(
            &self.ping,
            vec![
                "-c".to_owned(),
                "1".to_owned(),
                "-W".to_owned(),
                "2".to_owned(),
                target.to_string(),
            ],
        )
        .await
    }
}

async fn run<const N: usize>(binary: &PathBuf, args: [&str; N]) -> Result<CommandOutput> {
    run_owned(binary, args.into_iter().map(str::to_owned).collect()).await
}

async fn run_owned(binary: &PathBuf, args: Vec<String>) -> Result<CommandOutput> {
    let output = Command::new(binary).args(args).output().await?;
    let result = CommandOutput {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    if !result.is_success() {
        return Err(TailscaleError::Command(result.error_message()));
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn is_success(&self) -> bool {
        self.status == Some(0)
    }

    pub fn error_message(&self) -> String {
        let stderr = self.stderr.trim();
        if stderr.is_empty() {
            format!("exit status {:?}", self.status)
        } else {
            stderr.to_owned()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCheck {
    pub target: Ipv4Addr,
    pub route: String,
    pub via_tailscale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct TailscaleStatus {
    #[serde(rename = "BackendState")]
    pub backend_state: Option<String>,
    #[serde(rename = "Self")]
    pub self_node: Option<Node>,
    #[serde(rename = "Peer", default)]
    pub peers: BTreeMap<String, Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Node {
    #[serde(rename = "HostName")]
    pub host_name: Option<String>,
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "Online")]
    pub online: Option<bool>,
}

impl TailscaleStatus {
    pub fn advertised_routes(&self) -> Vec<String> {
        self.peers
            .values()
            .flat_map(|peer| peer.allowed_ips.iter())
            .filter(|ip| is_subnet_route(ip))
            .cloned()
            .collect()
    }
}

pub fn parse_status(json: &str) -> Result<TailscaleStatus> {
    Ok(serde_json::from_str(json)?)
}

fn is_subnet_route(value: &str) -> bool {
    let Some((addr, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if addr.contains(':') {
        prefix < 128
    } else {
        prefix < 32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_routes() {
        let json = r#"{"BackendState":"Running","Self":{"HostName":"edge","TailscaleIPs":["100.64.0.1"],"AllowedIPs":["100.64.0.1/32"],"Online":true},"Peer":{"node1":{"HostName":"home","AllowedIPs":["100.64.0.2/32","192.168.20.0/24"],"Online":true}}}"#;

        let status = parse_status(json).unwrap();

        assert_eq!(status.backend_state.as_deref(), Some("Running"));
        assert_eq!(status.advertised_routes(), vec!["192.168.20.0/24"]);
    }

    #[test]
    fn filters_host_routes() {
        assert!(!is_subnet_route("100.64.0.2/32"));
        assert!(!is_subnet_route("fd7a:115c:a1e0::1/128"));
        assert!(is_subnet_route("192.168.20.0/24"));
        assert!(is_subnet_route("fd7a:115c:a1e0::/64"));
    }
}
