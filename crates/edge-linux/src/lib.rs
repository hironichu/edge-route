use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;

pub type Result<T> = std::result::Result<T, LinuxError>;

#[derive(Debug, Error)]
pub enum LinuxError {
    #[error("linux command timed out after {0:?}")]
    Timeout(Duration),
    #[error("linux command failed: {0}")]
    Command(String),
    #[error("linux process failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linux {
    ip: PathBuf,
    timeout: Duration,
}

impl Default for Linux {
    fn default() -> Self {
        Self {
            ip: PathBuf::from("ip"),
            timeout: Duration::from_secs(5),
        }
    }
}

impl Linux {
    pub fn new(ip: impl Into<PathBuf>) -> Self {
        Self {
            ip: ip.into(),
            ..Self::default()
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn interface_addresses(&self, interface: &str) -> Result<Vec<Ipv4Addr>> {
        let output = self.run(["-4", "addr", "show", "dev", interface]).await?;
        Ok(parse_ipv4_addresses(&output.stdout))
    }

    pub async fn ensure_addr(&self, interface: &str, addr: Ipv4Addr) -> Result<bool> {
        let existing = self.interface_addresses(interface).await?;
        if existing.contains(&addr) {
            return Ok(false);
        }
        self.run_owned(vec![
            "addr".to_owned(),
            "add".to_owned(),
            format!("{addr}/32"),
            "dev".to_owned(),
            interface.to_owned(),
        ])
        .await?;
        Ok(true)
    }

    pub async fn delete_addr_if_present(&self, interface: &str, addr: Ipv4Addr) -> Result<bool> {
        let existing = self.interface_addresses(interface).await?;
        if !existing.contains(&addr) {
            return Ok(false);
        }
        self.run_owned(vec![
            "addr".to_owned(),
            "del".to_owned(),
            format!("{addr}/32"),
            "dev".to_owned(),
            interface.to_owned(),
        ])
        .await?;
        Ok(true)
    }

    async fn run<const N: usize>(&self, args: [&str; N]) -> Result<CommandOutput> {
        self.run_owned(args.into_iter().map(str::to_owned).collect())
            .await
    }

    async fn run_owned(&self, args: Vec<String>) -> Result<CommandOutput> {
        let output = timeout(self.timeout, Command::new(&self.ip).args(args).output())
            .await
            .map_err(|_| LinuxError::Timeout(self.timeout))??;
        let result = CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if !result.is_success() {
            return Err(LinuxError::Command(result.error_message()));
        }
        Ok(result)
    }
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

pub fn parse_ipv4_addresses(output: &str) -> Vec<Ipv4Addr> {
    output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|cidr| cidr.split_once('/').map(|(ip, _)| ip).or(Some(cidr)))
        .filter_map(|ip| ip.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_addr_show() {
        let output = r#"2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9000
    inet 10.0.0.4/24 metric 100 scope global dynamic ens3
       valid_lft 86399sec preferred_lft 86399sec
    inet 10.0.0.101/32 scope global ens3
"#;

        assert_eq!(
            parse_ipv4_addresses(output),
            vec![
                "10.0.0.4".parse::<Ipv4Addr>().unwrap(),
                "10.0.0.101".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }
}
