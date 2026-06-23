use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::errors::{EdgeCoreError, Result};
use crate::mapping::{EdgeConfig, Mapping};

pub fn validate_edge_config(config: &EdgeConfig) -> Result<()> {
    validate_interface_name("wan_interface", &config.wan_interface)?;
    validate_interface_name("tailscale_interface", &config.tailscale_interface)?;

    if config.home_cidrs.is_empty() {
        return Err(EdgeCoreError::validation(
            "at least one home CIDR must be configured",
        ));
    }

    for cidr in &config.home_cidrs {
        if cidr.addr().is_unspecified() {
            return Err(EdgeCoreError::validation(format!(
                "home CIDR cannot be unspecified: {cidr}"
            )));
        }
    }

    Ok(())
}

pub fn validate_mapping(mapping: &Mapping, config: &EdgeConfig) -> Result<()> {
    validate_name(&mapping.name)?;
    if let Some(public_ip) = mapping.public_ip {
        validate_public_ip(public_ip)?;
    }
    validate_edge_private_ip(mapping.edge_private_ip)?;
    validate_target_ip(mapping.target_ip, &config.home_cidrs)?;

    if mapping.public_ip == Some(mapping.edge_private_ip) {
        return Err(EdgeCoreError::validation(
            "public IP and edge private IP cannot match",
        ));
    }

    if mapping.edge_private_ip == mapping.target_ip {
        return Err(EdgeCoreError::validation(
            "edge private IP and target IP cannot match",
        ));
    }

    if mapping.target_port == Some(0) {
        return Err(EdgeCoreError::validation(
            "target port must be between 1 and 65535",
        ));
    }

    Ok(())
}

pub fn validate_mappings(mappings: &[Mapping], config: &EdgeConfig) -> Result<()> {
    let mut public_ips = HashSet::new();
    let mut edge_private_ips = HashSet::new();
    let mut target_ips = HashSet::new();

    for mapping in mappings {
        validate_mapping(mapping, config)?;

        if let Some(public_ip) = mapping.public_ip {
            if !public_ips.insert(public_ip) {
                return Err(EdgeCoreError::DuplicatePublicIp(public_ip));
            }
        }

        if !edge_private_ips.insert(mapping.edge_private_ip) {
            return Err(EdgeCoreError::DuplicateEdgePrivateIp(
                mapping.edge_private_ip,
            ));
        }

        if !target_ips.insert(mapping.target_ip) {
            return Err(EdgeCoreError::DuplicateTargetIp(mapping.target_ip));
        }
    }

    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(EdgeCoreError::validation("mapping name cannot be empty"));
    }

    if trimmed.len() > 63 {
        return Err(EdgeCoreError::validation(
            "mapping name cannot exceed 63 bytes",
        ));
    }

    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(EdgeCoreError::validation(
            "mapping name may only contain ASCII letters, digits, '-' and '_'",
        ));
    }

    Ok(())
}

fn validate_interface_name(field: &str, name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(EdgeCoreError::validation(format!(
            "{field} cannot be empty"
        )));
    }

    if trimmed.len() > 15 {
        return Err(EdgeCoreError::validation(format!(
            "{field} cannot exceed 15 bytes"
        )));
    }

    if trimmed.contains('/') || trimmed.contains('\0') || trimmed == "." || trimmed == ".." {
        return Err(EdgeCoreError::validation(format!(
            "{field} is not a valid Linux interface name"
        )));
    }

    Ok(())
}

fn validate_public_ip(ip: Ipv4Addr) -> Result<()> {
    if is_reserved_or_private(ip) {
        return Err(EdgeCoreError::validation(format!(
            "public IP must be globally routable: {ip}"
        )));
    }

    Ok(())
}

fn validate_edge_private_ip(ip: Ipv4Addr) -> Result<()> {
    if !ip.is_private() {
        return Err(EdgeCoreError::validation(format!(
            "edge private IP must be RFC1918 private: {ip}"
        )));
    }

    Ok(())
}

fn validate_target_ip(ip: Ipv4Addr, home_cidrs: &[Ipv4Net]) -> Result<()> {
    let Some(cidr) = home_cidrs.iter().find(|cidr| cidr.contains(&ip)) else {
        return Err(EdgeCoreError::validation(format!(
            "target IP is outside configured home CIDRs: {ip}"
        )));
    };

    if is_network_or_broadcast(ip, *cidr) {
        return Err(EdgeCoreError::validation(format!(
            "target IP cannot be network or broadcast address: {ip}"
        )));
    }

    Ok(())
}

fn is_reserved_or_private(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || octets[0] == 100 && (64..=127).contains(&octets[1])
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 0
        || octets[0] == 192 && octets[1] == 0 && octets[2] == 2
        || octets[0] == 198 && octets[1] == 51 && octets[2] == 100
        || octets[0] == 203 && octets[1] == 0 && octets[2] == 113
        || octets[0] >= 240
}

fn is_network_or_broadcast(ip: Ipv4Addr, cidr: Ipv4Net) -> bool {
    if cidr.prefix_len() >= 31 {
        return false;
    }

    ip == cidr.network() || ip == cidr.broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::Mapping;

    fn config() -> EdgeConfig {
        EdgeConfig::new(
            "ens3",
            "tailscale0",
            vec!["192.168.20.0/24".parse().unwrap()],
        )
    }

    fn mapping() -> Mapping {
        Mapping::new(
            "prod_vm_1",
            Some("8.8.8.8".parse().unwrap()),
            "10.0.0.101".parse().unwrap(),
            "192.168.20.42".parse().unwrap(),
        )
    }

    #[test]
    fn accepts_valid_mapping_inside_home_cidr() {
        validate_mapping(&mapping(), &config()).unwrap();
    }

    #[test]
    fn rejects_target_outside_home_cidrs() {
        let mut mapping = mapping();
        mapping.target_ip = "192.168.30.42".parse().unwrap();

        let err = validate_mapping(&mapping, &config()).unwrap_err();

        assert_eq!(
            err,
            EdgeCoreError::validation("target IP is outside configured home CIDRs: 192.168.30.42")
        );
    }

    #[test]
    fn rejects_duplicate_public_ip() {
        let first = mapping();
        let mut second = mapping();
        second.edge_private_ip = "10.0.0.102".parse().unwrap();
        second.target_ip = "192.168.20.43".parse().unwrap();

        let err = validate_mappings(&[first, second], &config()).unwrap_err();

        assert_eq!(
            err,
            EdgeCoreError::DuplicatePublicIp("8.8.8.8".parse().unwrap())
        );
    }

    #[test]
    fn rejects_network_and_broadcast_targets() {
        let mut network = mapping();
        network.target_ip = "192.168.20.0".parse().unwrap();

        let mut broadcast = mapping();
        broadcast.target_ip = "192.168.20.255".parse().unwrap();

        assert!(validate_mapping(&network, &config()).is_err());
        assert!(validate_mapping(&broadcast, &config()).is_err());
    }

    #[test]
    fn rejects_invalid_public_ip() {
        let mut mapping = mapping();
        mapping.public_ip = Some("10.0.0.1".parse().unwrap());

        let err = validate_mapping(&mapping, &config()).unwrap_err();

        assert_eq!(
            err,
            EdgeCoreError::validation("public IP must be globally routable: 10.0.0.1")
        );
    }
}
