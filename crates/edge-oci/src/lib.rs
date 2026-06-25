use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub type Result<T> = std::result::Result<T, OciError>;

#[derive(Debug, Error)]
pub enum OciError {
    #[error("OCI CLI failed: {0}")]
    Command(String),
    #[error("OCI CLI JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("OCI CLI process failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("OCI CLI timed out after {0}s")]
    Timeout(u64),
    #[error("OCI API config failed: {0}")]
    Config(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciAuthConfig {
    InstancePrincipal {
        region: String,
    },
    ApiKey {
        region: String,
        tenancy_id: String,
        user_id: String,
        fingerprint: String,
        private_key_path: PathBuf,
    },
}

impl OciAuthConfig {
    pub fn region(&self) -> &str {
        match self {
            Self::InstancePrincipal { region } | Self::ApiKey { region, .. } => region,
        }
    }

    pub fn api_key_from_env(region: impl Into<String>) -> Result<Self> {
        let tenancy_id = required_env("OCI_TENANCY_ID")?;
        let user_id = required_env("OCI_USER_ID")?;
        let fingerprint = required_env("OCI_FINGERPRINT")?;
        let private_key_path = PathBuf::from(required_env("OCI_PRIVATE_KEY_PATH")?);
        Ok(Self::ApiKey {
            region: region.into(),
            tenancy_id,
            user_id,
            fingerprint,
            private_key_path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciApiClient {
    auth: OciAuthConfig,
}

impl OciApiClient {
    pub fn new(auth: OciAuthConfig) -> Self {
        Self { auth }
    }

    pub fn auth(&self) -> &OciAuthConfig {
        &self.auth
    }

    pub fn list_public_ips(&self, compartment_id: &str) -> OciApiRequest {
        OciApiRequest::get(
            self.endpoint("iaas"),
            format!("/20160918/publicIps?compartmentId={compartment_id}&scope=REGION"),
        )
    }

    pub fn assign_reserved_public_ip(
        &self,
        public_ip_id: &str,
        private_ip_id: &str,
    ) -> Result<OciApiRequest> {
        OciApiRequest::put(
            self.endpoint("iaas"),
            format!("/20160918/publicIps/{public_ip_id}"),
            &UpdatePublicIpDetails {
                private_ip_id: Some(private_ip_id.to_owned()),
            },
        )
    }

    pub fn unassign_reserved_public_ip(&self, public_ip_id: &str) -> Result<OciApiRequest> {
        OciApiRequest::put(
            self.endpoint("iaas"),
            format!("/20160918/publicIps/{public_ip_id}"),
            &UpdatePublicIpDetails {
                private_ip_id: None,
            },
        )
    }

    pub fn create_private_ip(
        &self,
        vnic_id: &str,
        display_name: Option<&str>,
    ) -> Result<OciApiRequest> {
        OciApiRequest::post(
            self.endpoint("iaas"),
            "/20160918/privateIps".to_owned(),
            &CreatePrivateIpDetails {
                vnic_id: vnic_id.to_owned(),
                display_name: display_name.map(str::to_owned),
            },
        )
    }

    pub fn create_reserved_public_ip(
        &self,
        compartment_id: &str,
        private_ip_id: &str,
        display_name: Option<&str>,
    ) -> Result<OciApiRequest> {
        OciApiRequest::post(
            self.endpoint("iaas"),
            "/20160918/publicIps".to_owned(),
            &CreatePublicIpDetails {
                compartment_id: compartment_id.to_owned(),
                lifetime: "RESERVED".to_owned(),
                private_ip_id: Some(private_ip_id.to_owned()),
                display_name: display_name.map(str::to_owned),
            },
        )
    }

    pub fn add_nsg_security_rules(
        &self,
        nsg_id: &str,
        rules: &[IngressSecurityRule],
    ) -> Result<OciApiRequest> {
        OciApiRequest::post(
            self.endpoint("iaas"),
            format!("/20160918/networkSecurityGroups/{nsg_id}/actions/addSecurityRules"),
            &AddSecurityRulesDetails {
                security_rules: rules.to_vec(),
            },
        )
    }

    pub fn remove_nsg_security_rules(
        &self,
        nsg_id: &str,
        rule_ids: &[String],
    ) -> Result<OciApiRequest> {
        OciApiRequest::post(
            self.endpoint("iaas"),
            format!("/20160918/networkSecurityGroups/{nsg_id}/actions/removeSecurityRules"),
            &RemoveSecurityRulesDetails {
                security_rule_ids: rule_ids.to_vec(),
            },
        )
    }

    fn endpoint(&self, service: &str) -> String {
        format!("https://{service}.{}.oraclecloud.com", self.auth.region())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciHttpMethod {
    Get,
    Post,
    Put,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciApiRequest {
    pub method: OciHttpMethod,
    pub endpoint: String,
    pub path_and_query: String,
    pub body: Option<String>,
}

impl OciApiRequest {
    fn get(endpoint: String, path_and_query: String) -> Self {
        Self {
            method: OciHttpMethod::Get,
            endpoint,
            path_and_query,
            body: None,
        }
    }

    fn post<T: Serialize>(endpoint: String, path_and_query: String, body: &T) -> Result<Self> {
        Self::with_body(OciHttpMethod::Post, endpoint, path_and_query, body)
    }

    fn put<T: Serialize>(endpoint: String, path_and_query: String, body: &T) -> Result<Self> {
        Self::with_body(OciHttpMethod::Put, endpoint, path_and_query, body)
    }

    fn with_body<T: Serialize>(
        method: OciHttpMethod,
        endpoint: String,
        path_and_query: String,
        body: &T,
    ) -> Result<Self> {
        Ok(Self {
            method,
            endpoint,
            path_and_query,
            body: Some(serde_json::to_string(body)?),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatePrivateIpDetails {
    vnic_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatePublicIpDetails {
    compartment_id: String,
    lifetime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_ip_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePublicIpDetails {
    private_ip_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AddSecurityRulesDetails {
    security_rules: Vec<IngressSecurityRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveSecurityRulesDetails {
    security_rule_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressSecurityRule {
    pub protocol: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_options: Option<PortOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_options: Option<PortOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortOptions {
    pub destination_port_range: PortRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| OciError::Config(format!("missing {name}")))
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

    pub async fn version(&self) -> Result<CommandOutput> {
        self.run(["--version"]).await
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
        let timeout_seconds = 12;
        let output = timeout(
            Duration::from_secs(timeout_seconds),
            Command::new(&self.binary).args(args).output(),
        )
        .await
        .map_err(|_| OciError::Timeout(timeout_seconds))??;
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
    pub lifetime: Option<String>,
    pub scope: Option<String>,
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
        let json = r#"{"data":[{"id":"ocid1.publicip.x","ip-address":"152.1.2.3","private-ip-id":"ocid1.privateip.y","lifetime":"RESERVED","scope":"REGION","lifecycle-state":"AVAILABLE","display-name":"prod"}]}"#;

        let ips: Vec<PublicIp> = parse_list(json).unwrap();

        assert_eq!(ips[0].id, "ocid1.publicip.x");
        assert_eq!(ips[0].ip_address, "152.1.2.3".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ips[0].private_ip_id.as_deref(), Some("ocid1.privateip.y"));
        assert_eq!(ips[0].lifetime.as_deref(), Some("RESERVED"));
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

    #[test]
    fn builds_reserved_public_ip_reuse_request() {
        let client = OciApiClient::new(OciAuthConfig::InstancePrincipal {
            region: "eu-paris-1".to_owned(),
        });

        let request = client
            .assign_reserved_public_ip("ocid1.publicip.x", "ocid1.privateip.y")
            .unwrap();

        assert_eq!(request.method, OciHttpMethod::Put);
        assert_eq!(request.endpoint, "https://iaas.eu-paris-1.oraclecloud.com");
        assert_eq!(
            request.path_and_query,
            "/20160918/publicIps/ocid1.publicip.x"
        );
        assert_eq!(
            request.body.as_deref(),
            Some(r#"{"privateIpId":"ocid1.privateip.y"}"#)
        );
    }

    #[test]
    fn builds_nsg_ingress_rule_request() {
        let client = OciApiClient::new(OciAuthConfig::InstancePrincipal {
            region: "eu-paris-1".to_owned(),
        });
        let rule = IngressSecurityRule {
            protocol: "6".to_owned(),
            source: "0.0.0.0/0".to_owned(),
            tcp_options: Some(PortOptions {
                destination_port_range: PortRange {
                    min: 13306,
                    max: 13306,
                },
            }),
            udp_options: None,
            description: Some("EdgeRoute mysql".to_owned()),
        };

        let request = client
            .add_nsg_security_rules("ocid1.nsg.x", &[rule])
            .unwrap();

        assert_eq!(request.method, OciHttpMethod::Post);
        assert_eq!(
            request.path_and_query,
            "/20160918/networkSecurityGroups/ocid1.nsg.x/actions/addSecurityRules"
        );
        assert!(request
            .body
            .as_deref()
            .unwrap()
            .contains(r#""destinationPortRange":{"min":13306,"max":13306}"#));
    }
}
