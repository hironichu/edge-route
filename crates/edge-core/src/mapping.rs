use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::errors::{EdgeCoreError, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MappingId(String);

impl MappingId {
    pub fn new() -> Self {
        Self(format!("map_{}", Uuid::new_v4().simple()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for MappingId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MappingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MappingId {
    type Err = EdgeCoreError;

    fn from_str(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(EdgeCoreError::validation("mapping id cannot be empty"));
        }
        Ok(Self(trimmed.to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    All,
    Tcp,
    Udp,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::All
    }
}

impl FromStr for Protocol {
    type Err = EdgeCoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(EdgeCoreError::validation(format!(
                "unsupported protocol: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingMode {
    OneToOneSnat,
    PortForwardSnat,
}

impl Default for MappingMode {
    fn default() -> Self {
        Self::OneToOneSnat
    }
}

impl FromStr for MappingMode {
    type Err = EdgeCoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "one_to_one_snat" => Ok(Self::OneToOneSnat),
            "port_forward_snat" => Ok(Self::PortForwardSnat),
            other => Err(EdgeCoreError::validation(format!(
                "unsupported mapping mode: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingStatus {
    Pending,
    Active,
    Disabled,
    Degraded,
    Error,
}

impl Default for MappingStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciAuthMode {
    InstancePrincipal,
    ApiKey,
}

impl Default for OciAuthMode {
    fn default() -> Self {
        Self::InstancePrincipal
    }
}

impl FromStr for OciAuthMode {
    type Err = EdgeCoreError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "instance_principal" => Ok(Self::InstancePrincipal),
            "api_key" => Ok(Self::ApiKey),
            other => Err(EdgeCoreError::validation(format!(
                "unsupported OCI auth mode: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeConfig {
    pub wan_interface: String,
    pub tailscale_interface: String,
    pub home_cidrs: Vec<Ipv4Net>,
    pub oci_compartment_id: Option<String>,
    pub oci_vnic_id: Option<String>,
    pub oci_subnet_id: Option<String>,
    #[serde(default)]
    pub oci_nsg_ids: Vec<String>,
    pub oci_region: Option<String>,
    #[serde(default)]
    pub oci_auth: OciAuthMode,
    pub api_token: Option<String>,
}

impl EdgeConfig {
    pub fn new(
        wan_interface: impl Into<String>,
        tailscale_interface: impl Into<String>,
        home_cidrs: Vec<Ipv4Net>,
    ) -> Self {
        Self {
            wan_interface: wan_interface.into(),
            tailscale_interface: tailscale_interface.into(),
            home_cidrs,
            oci_compartment_id: None,
            oci_vnic_id: None,
            oci_subnet_id: None,
            oci_nsg_ids: Vec::new(),
            oci_region: None,
            oci_auth: OciAuthMode::default(),
            api_token: None,
        }
    }

    pub fn contains_home_target(&self, ip: Ipv4Addr) -> bool {
        self.home_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    pub id: MappingId,
    pub name: String,
    pub public_ip: Option<Ipv4Addr>,
    pub oci_public_ip_ocid: Option<String>,
    pub edge_private_ip: Ipv4Addr,
    pub oci_private_ip_ocid: Option<String>,
    pub target_ip: Ipv4Addr,
    pub public_port: Option<u16>,
    pub target_port: Option<u16>,
    pub protocol: Protocol,
    pub mode: MappingMode,
    pub enabled: bool,
    pub status: MappingStatus,
    pub last_error: Option<String>,
    pub health_status: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_checked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl Mapping {
    pub fn new(
        name: impl Into<String>,
        public_ip: Option<Ipv4Addr>,
        edge_private_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            id: MappingId::new(),
            name: name.into(),
            public_ip,
            oci_public_ip_ocid: None,
            edge_private_ip,
            oci_private_ip_ocid: None,
            target_ip,
            public_port: None,
            target_port: None,
            protocol: Protocol::default(),
            mode: MappingMode::default(),
            enabled: true,
            status: MappingStatus::default(),
            last_error: None,
            health_status: None,
            last_checked_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_id(mut self, id: MappingId) -> Self {
        self.id = id;
        self
    }

    pub fn mark_status(&mut self, status: MappingStatus) {
        self.status = status;
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.status = if enabled {
            MappingStatus::Pending
        } else {
            MappingStatus::Disabled
        };
        self.updated_at = OffsetDateTime::now_utc();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn mapping_id_rejects_empty_input() {
        let err = MappingId::from_str("  ").unwrap_err();

        assert_eq!(err, EdgeCoreError::validation("mapping id cannot be empty"));
    }

    #[test]
    fn mapping_uses_snake_case_wire_names() {
        let json = serde_json::to_string(&MappingMode::OneToOneSnat).unwrap();

        assert_eq!(json, "\"one_to_one_snat\"");

        let json = serde_json::to_string(&MappingMode::PortForwardSnat).unwrap();

        assert_eq!(json, "\"port_forward_snat\"");
    }
}
