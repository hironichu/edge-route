use edge_core::validation::validate_mappings;
use edge_core::{EdgeConfig, Mapping, MappingBackend, MappingMode, Protocol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRenderConfig {
    pub table_name: String,
}

impl Default for NftRenderConfig {
    fn default() -> Self {
        Self {
            table_name: "edge_nat".to_owned(),
        }
    }
}

pub fn render_nftables(
    mappings: &[Mapping],
    edge_config: &EdgeConfig,
    render_config: &NftRenderConfig,
) -> edge_core::Result<String> {
    validate_mappings(mappings, edge_config)?;

    let one_to_one: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| {
            mapping.enabled
                && mapping.backend == MappingBackend::Nft
                && mapping.mode == MappingMode::OneToOneSnat
        })
        .collect();
    let port_forwards: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| {
            mapping.enabled
                && mapping.backend == MappingBackend::Nft
                && mapping.mode == MappingMode::PortForwardSnat
        })
        .collect();

    let mut output = String::new();
    output.push_str(&format!(
        "destroy table ip {}\n\n",
        render_config.table_name
    ));
    output.push_str(&format!("table ip {} {{\n", render_config.table_name));
    output.push_str("    map edge_to_target {\n");
    output.push_str("        type ipv4_addr : ipv4_addr;\n");
    output.push_str("        elements = {\n");

    for mapping in one_to_one {
        output.push_str(&format!(
            "            {} : {},\n",
            mapping.edge_private_ip, mapping.target_ip
        ));
    }

    output.push_str("        }\n");
    output.push_str("    }\n\n");
    output.push_str("    chain prerouting {\n");
    output.push_str("        type nat hook prerouting priority dstnat; policy accept;\n\n");
    for mapping in port_forwards {
        let protocol = nft_protocol(mapping.protocol);
        let public_port = mapping.public_port.expect("validated public_port");
        let target_port = mapping.target_port.expect("validated target_port");
        output.push_str("        iifname \"");
        output.push_str(&edge_config.wan_interface);
        output.push_str("\" ip daddr ");
        output.push_str(&mapping.edge_private_ip.to_string());
        output.push(' ');
        output.push_str(protocol);
        output.push_str(" dport ");
        output.push_str(&public_port.to_string());
        output.push_str(" dnat to ");
        output.push_str(&mapping.target_ip.to_string());
        output.push(':');
        output.push_str(&target_port.to_string());
        output.push('\n');
    }
    if !mappings.iter().any(|mapping| {
        mapping.enabled
            && mapping.backend == MappingBackend::Nft
            && mapping.mode == MappingMode::OneToOneSnat
    }) {
        output.push('\n');
    }
    output.push_str("        dnat to ip daddr map @edge_to_target\n");
    output.push_str("    }\n\n");
    output.push_str("    chain postrouting {\n");
    output.push_str("        type nat hook postrouting priority srcnat; policy accept;\n\n");
    for cidr in &edge_config.target_cidrs {
        output.push_str("        oifname \"");
        output.push_str(&edge_config.netbird_interface);
        output.push_str("\" ip daddr ");
        output.push_str(&cidr.to_string());
        output.push_str(" masquerade\n");
    }
    output.push_str("    }\n");
    output.push_str("}\n");
    Ok(output)
}

fn nft_protocol(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::All => unreachable!("port-forward mappings cannot use protocol=all"),
    }
}

#[cfg(test)]
mod tests {
    use edge_core::{EdgeConfig, Mapping, MappingBackend, MappingMode, Protocol};

    use super::*;

    #[test]
    fn renders_static_mapping_rules() {
        let config = EdgeConfig::new("ens3", "wt0", vec!["192.168.20.0/24".parse().unwrap()]);
        let mapping = Mapping::new(
            "prod_vm_1",
            None,
            "10.0.0.101".parse().unwrap(),
            "192.168.20.42".parse().unwrap(),
        );

        let rendered = render_nftables(&[mapping], &config, &NftRenderConfig::default()).unwrap();

        assert!(rendered.contains("destroy table ip edge_nat"));
        assert!(rendered.contains("table ip edge_nat"));
        assert!(rendered.contains("10.0.0.101 : 192.168.20.42,"));
        assert!(rendered.contains("dnat to ip daddr map @edge_to_target"));
        assert!(rendered.contains("oifname \"wt0\" ip daddr 192.168.20.0/24 masquerade"));
    }

    #[test]
    fn explicit_nft_backend_preserves_rendered_output() {
        let config = EdgeConfig::new("ens3", "wt0", vec!["192.168.20.0/24".parse().unwrap()]);
        let default_mapping = Mapping::new(
            "prod_vm_1",
            None,
            "10.0.0.101".parse().unwrap(),
            "192.168.20.42".parse().unwrap(),
        );
        let mut explicit_mapping = default_mapping.clone();
        explicit_mapping.backend = MappingBackend::Nft;

        let default_rendered =
            render_nftables(&[default_mapping], &config, &NftRenderConfig::default()).unwrap();
        let explicit_rendered =
            render_nftables(&[explicit_mapping], &config, &NftRenderConfig::default()).unwrap();

        assert_eq!(default_rendered, explicit_rendered);
    }

    #[test]
    fn renders_port_forward_rules() {
        let config = EdgeConfig::new("ens3", "wt0", vec!["10.10.40.0/24".parse().unwrap()]);
        let mut tcp = Mapping::new(
            "mysql",
            Some("8.8.8.8".parse().unwrap()),
            "10.0.0.101".parse().unwrap(),
            "10.10.40.60".parse().unwrap(),
        );
        tcp.mode = MappingMode::PortForwardSnat;
        tcp.protocol = Protocol::Tcp;
        tcp.public_port = Some(13306);
        tcp.target_port = Some(3306);

        let mut udp = Mapping::new(
            "udp_service",
            Some("8.8.8.8".parse().unwrap()),
            "10.0.0.101".parse().unwrap(),
            "10.10.40.60".parse().unwrap(),
        );
        udp.mode = MappingMode::PortForwardSnat;
        udp.protocol = Protocol::Udp;
        udp.public_port = Some(14444);
        udp.target_port = Some(4444);

        let rendered = render_nftables(&[tcp, udp], &config, &NftRenderConfig::default()).unwrap();

        assert!(rendered.contains(
            "iifname \"ens3\" ip daddr 10.0.0.101 tcp dport 13306 dnat to 10.10.40.60:3306"
        ));
        assert!(rendered.contains(
            "iifname \"ens3\" ip daddr 10.0.0.101 udp dport 14444 dnat to 10.10.40.60:4444"
        ));
        assert!(rendered.contains("oifname \"wt0\" ip daddr 10.10.40.0/24 masquerade"));
    }

    #[test]
    fn renders_initial_netbird_cutover_rules() {
        let config = EdgeConfig::new(
            "enp0s6",
            "wt0",
            vec![
                "10.10.30.0/24".parse().unwrap(),
                "10.10.40.0/24".parse().unwrap(),
                "10.10.50.0/24".parse().unwrap(),
            ],
        );
        let first = Mapping::new(
            "target-88",
            None,
            "10.0.0.101".parse().unwrap(),
            "10.10.40.88".parse().unwrap(),
        );
        let second = Mapping::new(
            "target-89",
            None,
            "10.0.0.102".parse().unwrap(),
            "10.10.40.89".parse().unwrap(),
        );

        let rendered =
            render_nftables(&[first, second], &config, &NftRenderConfig::default()).unwrap();

        assert!(rendered.contains("10.0.0.101 : 10.10.40.88"));
        assert!(rendered.contains("10.0.0.102 : 10.10.40.89"));
        for cidr in ["10.10.30.0/24", "10.10.40.0/24", "10.10.50.0/24"] {
            assert!(rendered.contains(&format!("oifname \"wt0\" ip daddr {cidr} masquerade")));
        }
    }
}
