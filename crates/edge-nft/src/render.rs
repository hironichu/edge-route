use edge_core::validation::validate_mappings;
use edge_core::{EdgeConfig, Mapping, MappingMode};

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

    let active: Vec<&Mapping> = mappings
        .iter()
        .filter(|mapping| mapping.enabled && mapping.mode == MappingMode::OneToOneSnat)
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

    for mapping in active {
        output.push_str(&format!(
            "            {} : {},\n",
            mapping.edge_private_ip, mapping.target_ip
        ));
    }

    output.push_str("        }\n");
    output.push_str("    }\n\n");
    output.push_str("    chain prerouting {\n");
    output.push_str("        type nat hook prerouting priority dstnat; policy accept;\n\n");
    output.push_str("        dnat to ip daddr map @edge_to_target\n");
    output.push_str("    }\n\n");
    output.push_str("    chain postrouting {\n");
    output.push_str("        type nat hook postrouting priority srcnat; policy accept;\n\n");
    for cidr in &edge_config.home_cidrs {
        output.push_str("        oifname \"");
        output.push_str(&edge_config.tailscale_interface);
        output.push_str("\" ip daddr ");
        output.push_str(&cidr.to_string());
        output.push_str(" masquerade\n");
    }
    output.push_str("    }\n");
    output.push_str("}\n");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use edge_core::{EdgeConfig, Mapping};

    use super::*;

    #[test]
    fn renders_static_mapping_rules() {
        let config = EdgeConfig::new(
            "ens3",
            "tailscale0",
            vec!["192.168.20.0/24".parse().unwrap()],
        );
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
        assert!(rendered.contains("oifname \"tailscale0\" ip daddr 192.168.20.0/24 masquerade"));
    }
}
