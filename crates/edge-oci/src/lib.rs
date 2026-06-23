use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;
use tokio::process::Command;

pub type Result<T> = std::result::Result<T, OciError>;

#[derive(Debug, Error)]
pub enum OciError {
    #[error("OCI CLI failed: {0}")]
    Command(String),
    #[error("OCI CLI JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OCI CLI process failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciCli {
    binary: PathBuf,
}

impl Default for OciCli {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("oci"),
        }
    }
}

impl OciCli {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    pub async fn list_public_ips(&self, compartment_id: &str) -> Result<Vec<PublicIp>> {
        let output = self
            .run([
                "network",
                "public-ip",
                "list",
                "--scope",
                "REGION",
                "--compartment-id",
                compartment_id,
            ])
            .await?;
        parse_list(&output.stdout)
    }

    pub async fn create_private_ip(
        &self,
        vnic_id: &str,
        display_name: Option<&str>,
    ) -> Result<PrivateIp> {
        let mut args = vec![
            "network".to_owned(),
            "private-ip".to_owned(),
            "create".to_owned(),
            "--vnic-id".to_owned(),
            vnic_id.to_owned(),
        ];
        if let Some(display_name) = display_name {
            args.push("--display-name".to_owned());
            args.push(display_name.to_owned());
        }
        let output = self.run_owned(args).await?;
        parse_item(&output.stdout)
    }

    pub async fn create_reserved_public_ip(
        &self,
        compartment_id: &str,
        private_ip_id: &str,
        display_name: Option<&str>,
    ) -> Result<PublicIp> {
        let mut args = vec![
            "network".to_owned(),
            "public-ip".to_owned(),
            "create".to_owned(),
            "--compartment-id".to_owned(),
            compartment_id.to_owned(),
            "--lifetime".to_owned(),
            "RESERVED".to_owned(),
            "--private-ip-id".to_owned(),
            private_ip_id.to_owned(),
        ];
        if let Some(display_name) = display_name {
            args.push("--display-name".to_owned());
            args.push(display_name.to_owned());
        }
        let output = self.run_owned(args).await?;
        parse_item(&output.stdout)
    }

    pub async fn delete_public_ip(&self, public_ip_id: &str) -> Result<()> {
        self.run([
            "network",
            "public-ip",
            "delete",
            "--public-ip-id",
            public_ip_id,
            "--force",
        ])
        .await?;
        Ok(())
    }

    pub async fn delete_private_ip(&self, private_ip_id: &str) -> Result<()> {
        self.run([
            "network",
            "private-ip",
            "delete",
            "--private-ip-id",
            private_ip_id,
            "--force",
        ])
        .await?;
        Ok(())
    }

    pub async fn get_vnic(&self, vnic_id: &str) -> Result<Vnic> {
        let output = self
            .run(["network", "vnic", "get", "--vnic-id", vnic_id])
            .await?;
        parse_item(&output.stdout)
    }

    pub async fn validate_forwarding_vnic(&self, vnic_id: &str) -> Result<Vnic> {
        let vnic = self.get_vnic(vnic_id).await?;
        validate_vnic_forwarding(&vnic)?;
        Ok(vnic)
    }

    async fn run<const N: usize>(&self, args: [&str; N]) -> Result<CommandOutput> {
        self.run_owned(args.into_iter().map(str::to_owned).collect())
            .await
    }

    async fn run_owned(&self, args: Vec<String>) -> Result<CommandOutput> {
        let output = Command::new(&self.binary).args(args).output().await?;
        let result = CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if !result.is_success() {
            return Err(OciError::Command(result.error_message()));
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PublicIp {
    pub id: String,
    #[serde(rename = "ip-address")]
    pub ip_address: Ipv4Addr,
    #[serde(rename = "private-ip-id")]
    pub private_ip_id: Option<String>,
    #[serde(rename = "lifecycle-state")]
    pub lifecycle_state: Option<String>,
    #[serde(rename = "display-name")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PrivateIp {
    pub id: String,
    #[serde(rename = "ip-address")]
    pub ip_address: Ipv4Addr,
    #[serde(rename = "vnic-id")]
    pub vnic_id: Option<String>,
    #[serde(rename = "display-name")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Vnic {
    pub id: String,
    #[serde(rename = "display-name")]
    pub display_name: Option<String>,
    #[serde(rename = "skip-source-dest-check")]
    pub skip_source_dest_check: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ListResponse<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct ItemResponse<T> {
    data: T,
}

pub fn parse_list<T: for<'de> Deserialize<'de>>(json: &str) -> Result<Vec<T>> {
    Ok(serde_json::from_str::<ListResponse<T>>(json)?.data)
}

pub fn parse_item<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T> {
    Ok(serde_json::from_str::<ItemResponse<T>>(json)?.data)
}

pub fn validate_vnic_forwarding(vnic: &Vnic) -> Result<()> {
    if vnic.skip_source_dest_check == Some(true) {
        Ok(())
    } else {
        Err(OciError::Command(format!(
            "VNIC {} has source/destination checks enabled; disable skip-source-dest-check before forwarding",
            vnic.id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_public_ip_list() {
        let json = r#"{"data":[{"id":"ocid1.publicip.x","ip-address":"152.1.2.3","private-ip-id":"ocid1.privateip.y","lifecycle-state":"AVAILABLE","display-name":"prod"}]}"#;

        let ips: Vec<PublicIp> = parse_list(json).unwrap();

        assert_eq!(ips[0].id, "ocid1.publicip.x");
        assert_eq!(ips[0].ip_address, "152.1.2.3".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ips[0].private_ip_id.as_deref(), Some("ocid1.privateip.y"));
    }

    #[test]
    fn parses_private_ip_create() {
        let json = r#"{"data":{"id":"ocid1.privateip.x","ip-address":"10.0.0.101","vnic-id":"ocid1.vnic.x","display-name":"prod"}}"#;

        let private_ip: PrivateIp = parse_item(json).unwrap();

        assert_eq!(
            private_ip.ip_address,
            "10.0.0.101".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(private_ip.vnic_id.as_deref(), Some("ocid1.vnic.x"));
    }

    #[test]
    fn validates_vnic_source_destination_check() {
        let json =
            r#"{"data":{"id":"ocid1.vnic.x","display-name":"edge","skip-source-dest-check":true}}"#;
        let vnic: Vnic = parse_item(json).unwrap();
        validate_vnic_forwarding(&vnic).unwrap();

        let blocked = Vnic {
            skip_source_dest_check: Some(false),
            ..vnic
        };
        assert!(validate_vnic_forwarding(&blocked).is_err());
    }
}
