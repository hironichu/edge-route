use std::net::Ipv4Addr;
use std::path::PathBuf;

use edge_core::{EdgeConfig, Mapping, MappingBackend, MappingMode, Protocol};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, XdpError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum XdpError {
    #[error("XDP mappings are present but XDP is disabled: {0}")]
    Disabled(String),
    #[error("XDP config is invalid: {0}")]
    Config(String),
    #[error("XDP mapping {0} is invalid: {1}")]
    Mapping(String, String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XdpAttachMode {
    #[default]
    Skb,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpConfig {
    pub enabled: bool,
    pub interface: String,
    pub pin_path: PathBuf,
    pub attach_mode: XdpAttachMode,
}

impl XdpConfig {
    pub fn disabled(interface: impl Into<String>) -> Self {
        Self {
            enabled: false,
            interface: interface.into(),
            pin_path: PathBuf::from("/sys/fs/bpf/edgeroute"),
            attach_mode: XdpAttachMode::default(),
        }
    }

    pub fn enabled(interface: impl Into<String>, pin_path: impl Into<PathBuf>) -> Self {
        Self {
            enabled: true,
            interface: interface.into(),
            pin_path: pin_path.into(),
            attach_mode: XdpAttachMode::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpPlan {
    pub interface: String,
    pub pin_path: PathBuf,
    pub attach_mode: XdpAttachMode,
    pub entries: Vec<XdpForwardEntry>,
}

impl XdpPlan {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpForwardEntry {
    pub mapping_id: String,
    pub name: String,
    pub key: XdpMapKey,
    pub value: XdpMapValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpMapKey {
    pub edge_private_ip: Ipv4Addr,
    pub protocol: Protocol,
    pub public_port: u16,
}

impl XdpMapKey {
    pub fn bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[0..4].copy_from_slice(&self.edge_private_ip.octets());
        bytes[4..6].copy_from_slice(&self.public_port.to_be_bytes());
        bytes[6] = protocol_number(self.protocol);
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpMapValue {
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub flags: u16,
}

impl XdpMapValue {
    pub fn bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[0..4].copy_from_slice(&self.target_ip.octets());
        bytes[4..6].copy_from_slice(&self.target_port.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.flags.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpPlugin {
    config: XdpConfig,
}

impl XdpPlugin {
    pub fn new(config: XdpConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &XdpConfig {
        &self.config
    }

    pub fn plan(&self, mappings: &[Mapping], edge_config: &EdgeConfig) -> Result<XdpPlan> {
        validate_config(&self.config)?;
        let xdp_mappings: Vec<&Mapping> = mappings
            .iter()
            .filter(|mapping| mapping.enabled && mapping.backend == MappingBackend::Xdp)
            .collect();

        if !self.config.enabled && !xdp_mappings.is_empty() {
            let names = xdp_mappings
                .iter()
                .map(|mapping| mapping.name.as_str())
                .collect::<Vec<_>>()
                .join(",");
            return Err(XdpError::Disabled(names));
        }

        let mut entries = Vec::with_capacity(xdp_mappings.len());
        for mapping in xdp_mappings {
            entries.push(plan_entry(mapping, edge_config)?);
        }

        Ok(XdpPlan {
            interface: self.config.interface.clone(),
            pin_path: self.config.pin_path.clone(),
            attach_mode: self.config.attach_mode,
            entries,
        })
    }
}

fn validate_config(config: &XdpConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }
    if config.interface.trim().is_empty() {
        return Err(XdpError::Config("interface cannot be empty".to_owned()));
    }
    if config.pin_path.as_os_str().is_empty() {
        return Err(XdpError::Config("pin_path cannot be empty".to_owned()));
    }
    if !config.pin_path.is_absolute() {
        return Err(XdpError::Config("pin_path must be absolute".to_owned()));
    }
    Ok(())
}

fn plan_entry(mapping: &Mapping, edge_config: &EdgeConfig) -> Result<XdpForwardEntry> {
    if mapping.mode != MappingMode::PortForwardSnat {
        return Err(XdpError::Mapping(
            mapping.id.to_string(),
            "only port-forward mappings can use XDP".to_owned(),
        ));
    }
    if mapping.protocol == Protocol::All {
        return Err(XdpError::Mapping(
            mapping.id.to_string(),
            "XDP mappings must be tcp or udp".to_owned(),
        ));
    }
    let public_port = mapping.public_port.ok_or_else(|| {
        XdpError::Mapping(
            mapping.id.to_string(),
            "XDP mappings require public_port".to_owned(),
        )
    })?;
    let target_port = mapping.target_port.ok_or_else(|| {
        XdpError::Mapping(
            mapping.id.to_string(),
            "XDP mappings require target_port".to_owned(),
        )
    })?;
    if !edge_config.contains_home_target(mapping.target_ip) {
        return Err(XdpError::Mapping(
            mapping.id.to_string(),
            format!(
                "target IP is outside configured home CIDRs: {}",
                mapping.target_ip
            ),
        ));
    }

    Ok(XdpForwardEntry {
        mapping_id: mapping.id.to_string(),
        name: mapping.name.clone(),
        key: XdpMapKey {
            edge_private_ip: mapping.edge_private_ip,
            protocol: mapping.protocol,
            public_port,
        },
        value: XdpMapValue {
            target_ip: mapping.target_ip,
            target_port,
            flags: 0,
        },
    })
}

fn protocol_number(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::All => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_core::{EdgeConfig, Mapping, MappingBackend, MappingMode, Protocol};

    fn config() -> EdgeConfig {
        EdgeConfig::new("ens3", "tailscale0", vec!["10.10.40.0/24".parse().unwrap()])
    }

    fn xdp_mapping() -> Mapping {
        let mut mapping = Mapping::new(
            "mysql",
            Some("8.8.8.8".parse().unwrap()),
            "10.0.0.101".parse().unwrap(),
            "10.10.40.60".parse().unwrap(),
        );
        mapping.mode = MappingMode::PortForwardSnat;
        mapping.backend = MappingBackend::Xdp;
        mapping.protocol = Protocol::Tcp;
        mapping.public_port = Some(13306);
        mapping.target_port = Some(3306);
        mapping
    }

    #[test]
    fn plans_xdp_port_forward_map_entry() {
        let plugin = XdpPlugin::new(XdpConfig::enabled("ens3", "/sys/fs/bpf/edgeroute"));
        let mapping = xdp_mapping();

        let plan = plugin.plan(&[mapping], &config()).unwrap();

        assert_eq!(plan.interface, "ens3");
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(
            plan.entries[0].key.edge_private_ip,
            "10.0.0.101".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            plan.entries[0].value.target_ip,
            "10.10.40.60".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn serializes_key_and_value_in_network_order() {
        let key = XdpMapKey {
            edge_private_ip: "10.0.0.101".parse().unwrap(),
            protocol: Protocol::Tcp,
            public_port: 13306,
        };
        let value = XdpMapValue {
            target_ip: "10.10.40.60".parse().unwrap(),
            target_port: 3306,
            flags: 0,
        };

        assert_eq!(key.bytes(), [10, 0, 0, 101, 0x33, 0xfa, 6, 0]);
        assert_eq!(value.bytes(), [10, 10, 40, 60, 0x0c, 0xea, 0, 0]);
    }

    #[test]
    fn disabled_plugin_rejects_xdp_mappings() {
        let plugin = XdpPlugin::new(XdpConfig::disabled("ens3"));
        let mapping = xdp_mapping();

        let err = plugin.plan(&[mapping], &config()).unwrap_err();

        assert!(matches!(err, XdpError::Disabled(_)));
    }
}
