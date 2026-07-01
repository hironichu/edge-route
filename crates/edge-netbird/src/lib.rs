use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::process::Command;

pub type Result<T> = std::result::Result<T, NetbirdError>;

#[derive(Debug, Error)]
pub enum NetbirdError {
    #[error("command failed: {0}")]
    Command(String),
    #[error("netbird JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("process failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbirdCli {
    netbird: PathBuf,
    ip: PathBuf,
    ping: PathBuf,
}

impl Default for NetbirdCli {
    fn default() -> Self {
        Self {
            netbird: PathBuf::from("netbird"),
            ip: PathBuf::from("ip"),
            ping: PathBuf::from("ping"),
        }
    }
}

impl NetbirdCli {
    pub fn new(
        netbird: impl Into<PathBuf>,
        ip: impl Into<PathBuf>,
        ping: impl Into<PathBuf>,
    ) -> Self {
        Self {
            netbird: netbird.into(),
            ip: ip.into(),
            ping: ping.into(),
        }
    }

    pub async fn status(&self) -> Result<NetbirdStatus> {
        let output = run(&self.netbird, ["status", "--json"]).await?;
        parse_status(&output.stdout)
    }

    pub async fn route_get(&self, target: Ipv4Addr) -> Result<RouteCheck> {
        let output = run_owned(
            &self.ip,
            vec!["route".to_owned(), "get".to_owned(), target.to_string()],
        )
        .await?;
        let route = output.stdout.trim().to_owned();
        Ok(RouteCheck {
            target,
            interface: parse_route_interface(&route).map(str::to_owned),
            route,
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
        return Err(NetbirdError::Command(result.error_message()));
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
    pub interface: Option<String>,
}

impl RouteCheck {
    pub fn uses_interface(&self, expected: &str) -> bool {
        self.interface.as_deref() == Some(expected)
    }
}

fn parse_route_interface(route: &str) -> Option<&str> {
    let mut fields = route.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next();
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetbirdStatus {
    #[serde(default, deserialize_with = "null_to_default")]
    pub peers: PeerOverview,
    pub cli_version: Option<String>,
    pub daemon_version: Option<String>,
    pub daemon_status: Option<String>,
    #[serde(default)]
    pub management: ServiceStatus,
    #[serde(default)]
    pub signal: ServiceStatus,
    pub netbird_ip: Option<String>,
    pub netbird_ipv6: Option<String>,
    pub uses_kernel_interface: Option<bool>,
    pub fqdn: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub networks: Vec<String>,
    #[serde(default)]
    pub lazy_connection_enabled: bool,
}

impl NetbirdStatus {
    pub fn advertised_networks(&self) -> Vec<String> {
        self.peers
            .details
            .iter()
            .flat_map(|peer| peer.networks.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn daemon_connected(&self) -> bool {
        self.daemon_status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("connected"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerOverview {
    #[serde(default)]
    pub total: usize,
    #[serde(default)]
    pub connected: usize,
    #[serde(default)]
    pub details: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Peer {
    pub fqdn: Option<String>,
    pub netbird_ip: Option<String>,
    pub netbird_ipv6: Option<String>,
    pub status: Option<String>,
    pub connection_type: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub networks: Vec<String>,
}

impl Peer {
    pub fn is_healthy(&self) -> bool {
        self.status.as_deref().is_some_and(|status| {
            status.eq_ignore_ascii_case("connected") || status.eq_ignore_ascii_case("idle")
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    #[serde(default)]
    pub connected: bool,
}

fn null_to_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

pub fn parse_status(json: &str) -> Result<NetbirdStatus> {
    Ok(serde_json::from_str(json)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = r#"{
      "peers":{"total":3,"connected":1,"details":[
        {"fqdn":"idle.bird.home","netbirdIp":"100.64.34.182","netbirdIpv6":"fd66::1","publicKey":"secret","status":"Idle","connectionType":"-","relayAddress":"rels://internal","networks":null},
        {"fqdn":"router.bird.home","netbirdIp":"100.64.94.84","status":"Connected","connectionType":"Relayed","networks":["10.10.40.0/24","10.10.30.0/24"]},
        {"fqdn":"down.bird.home","netbirdIp":"100.64.49.18","status":"Disconnected","networks":null}
      ]},
      "cliVersion":"0.73.2","daemonVersion":"0.73.2","daemonStatus":"Connected",
      "management":{"url":"https://private.example","connected":true,"error":""},
      "signal":{"url":"https://private.example","connected":true,"error":""},
      "netbirdIp":"100.64.65.67/16","netbirdIpv6":"fd66:a144::1/64",
      "publicKey":"secret","usesKernelInterface":true,"fqdn":"mainvnic.bird.home",
      "networks":null,"lazyConnectionEnabled":true
    }"#;

    #[test]
    fn parses_netbird_status_and_networks() {
        let status = parse_status(STATUS).unwrap();

        assert!(status.daemon_connected());
        assert_eq!(status.netbird_ipv6.as_deref(), Some("fd66:a144::1/64"));
        assert_eq!(
            status.advertised_networks(),
            vec!["10.10.30.0/24", "10.10.40.0/24"]
        );
        assert!(status.peers.details[0].is_healthy());
        assert!(status.peers.details[1].is_healthy());
        assert!(!status.peers.details[2].is_healthy());
    }

    #[test]
    fn serialization_omits_sensitive_cli_fields() {
        let value = serde_json::to_value(parse_status(STATUS).unwrap()).unwrap();
        let encoded = value.to_string();

        assert!(!encoded.contains("publicKey"));
        assert!(!encoded.contains("relayAddress"));
        assert!(!encoded.contains("private.example"));
        assert_eq!(value["management"]["connected"], true);
    }

    #[test]
    fn accepts_missing_optional_fields() {
        let status = parse_status(r#"{"daemonStatus":"Disconnected"}"#).unwrap();

        assert!(!status.daemon_connected());
        assert!(status.peers.details.is_empty());
        assert!(status.networks.is_empty());
    }

    #[test]
    fn parses_main_and_policy_table_routes_exactly() {
        let main = "100.64.34.182 dev wt0 src 100.64.65.67 uid 1001";
        let policy = "10.10.40.89 dev wt0 table netbird src 100.64.65.67 uid 1001";

        assert_eq!(parse_route_interface(main), Some("wt0"));
        assert_eq!(parse_route_interface(policy), Some("wt0"));
        assert_ne!(parse_route_interface(policy), Some("wt"));
        assert_eq!(parse_route_interface("unreachable 10.0.0.1"), None);
    }
}
