use std::str::FromStr;
use std::sync::{LazyLock, Mutex};

use axum::http::{HeaderMap, Method, StatusCode};
use bytes::Bytes;
use edge_core::{
    Event, EventLevel, Mapping, MappingBackend, MappingId, MappingMode, MappingStatus, Protocol,
};
use edge_netbird::{NetbirdStatus, Peer, PeerOverview, ServiceStatus};
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::GatewayError;

static STORE: LazyLock<Mutex<MockStore>> = LazyLock::new(|| Mutex::new(MockStore::new()));

struct MockStore {
    mappings: Vec<Mapping>,
    events: Vec<Event>,
}

struct MappingSeed {
    id: &'static str,
    name: &'static str,
    edge_ip: &'static str,
    target_ip: &'static str,
    mode: MappingMode,
    protocol: Protocol,
    public_port: Option<u16>,
    target_port: Option<u16>,
    backend: MappingBackend,
    status: MappingStatus,
}

#[derive(Debug, Deserialize)]
struct CreateMapping {
    name: String,
    public_ip: Option<std::net::Ipv4Addr>,
    edge_private_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    public_port: Option<u16>,
    target_port: Option<u16>,
    protocol: Option<Protocol>,
    mode: Option<MappingMode>,
    backend: Option<MappingBackend>,
}

pub async fn handle(
    method: Method,
    path: &str,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), GatewayError> {
    let path = path.split('?').next().unwrap_or(path);
    let mut store = STORE
        .lock()
        .map_err(|_| GatewayError::bad_gateway("mock store lock poisoned"))?;
    let response = match (method.clone(), path) {
        (Method::GET, "/v1/status") => json!({
            "wan_interface": "ens3",
            "netbird_interface": "wt0",
            "target_cidrs": ["10.10.30.0/24", "10.10.40.0/24", "10.10.50.0/24"],
            "mappings": store.mappings.len(),
            "enabled_mappings": store.mappings.iter().filter(|m| m.enabled).count(),
        }),
        (Method::GET, "/v1/mappings") => {
            serde_json::to_value(&store.mappings).map_err(GatewayError::bad_gateway)?
        }
        (Method::POST, "/v1/mappings") => {
            let input: CreateMapping =
                serde_json::from_slice(&body).map_err(GatewayError::bad_gateway)?;
            let mut mapping = Mapping::new(
                input.name,
                input.public_ip,
                input.edge_private_ip,
                input.target_ip,
            );
            mapping.public_port = input.public_port;
            mapping.target_port = input.target_port;
            mapping.protocol = input.protocol.unwrap_or_default();
            mapping.mode = input.mode.unwrap_or_default();
            mapping.backend = input.backend.unwrap_or_default();
            mapping.status = MappingStatus::Pending;
            store.mappings.push(mapping.clone());
            serde_json::to_value(mapping).map_err(GatewayError::bad_gateway)?
        }
        (Method::POST, "/v1/apply/dry-run") => {
            return Ok((StatusCode::OK, HeaderMap::new(), Bytes::from(nft_text())));
        }
        (Method::POST, "/v1/reconcile") => json!({
            "generation_id": 618,
            "added_addresses": ["10.0.0.101"],
            "removed_addresses": [],
            "xdp_plan_entries": 0,
            "nftables_config": nft_text(),
        }),
        (Method::GET, "/v1/netbird/status") => {
            serde_json::to_value(netbird_status()).map_err(GatewayError::bad_gateway)?
        }
        (Method::GET, "/v1/netbird/networks") => json!(["10.10.40.0/24"]),
        (Method::GET, "/v1/events") => {
            serde_json::to_value(&store.events).map_err(GatewayError::bad_gateway)?
        }
        (Method::GET, "/v1/analytics") => json!({
            "mapping_total": store.mappings.len(),
            "mapping_enabled": store.mappings.iter().filter(|m| m.enabled).count(),
            "mapping_status": {
                "active": store.mappings.iter().filter(|m| m.status == MappingStatus::Active).count(),
                "degraded": store.mappings.iter().filter(|m| m.status == MappingStatus::Degraded).count(),
            },
            "mapping_backend": { "nft": store.mappings.len() },
            "event_level": { "warn": 1, "info": 1, "debug": 1 },
            "problem_mappings": store.mappings.iter().filter(|m| matches!(m.status, MappingStatus::Degraded | MappingStatus::Error)).count(),
        }),
        (Method::GET, "/v1/topology") => json!({
            "wan_interface": "ens3",
            "netbird_interface": "wt0",
            "target_cidrs": ["10.10.40.0/24"],
            "flows": store.mappings.iter().map(|mapping| json!({
                "id": mapping.id.to_string(),
                "name": mapping.name,
                "public_endpoint": endpoint(mapping.public_ip.map(|ip| ip.to_string()), mapping.public_port),
                "edge_private_ip": mapping.edge_private_ip.to_string(),
                "target_endpoint": endpoint(Some(mapping.target_ip.to_string()), mapping.target_port),
                "protocol": wire_name(&mapping.protocol),
                "mode": wire_name(&mapping.mode),
                "backend": wire_name(&mapping.backend),
                "status": wire_name(&mapping.status),
                "enabled": mapping.enabled,
            })).collect::<Vec<_>>(),
        }),
        (Method::GET, "/v1/oci/status") => json!({
            "auth_mode": "instance_principal",
            "region": "eu-paris-1",
            "compartment_id_configured": true,
            "vnic_id_configured": true,
            "subnet_id_configured": true,
            "nsg_count": 1,
            "api_key_env_ready": false,
            "env": {
                "tenancy_id": false,
                "user_id": false,
                "fingerprint": false,
                "private_key_path": false
            },
            "cli_available": true,
            "cli_version": "oci-cli fixture",
            "compartment_id": "ocid1.compartment.oc1..fixture",
            "vnic_id": "ocid1.vnic.oc1..fixture",
            "subnet_id": "ocid1.subnet.oc1..fixture",
            "nsg_ids": ["ocid1.networksecuritygroup.oc1..fixture"]
        }),
        (Method::POST, "/v1/oci/allocate") => json!({
            "id": "fixture", "name": "fixture",
            "public_ip": "152.0.0.10", "edge_private_ip": "10.0.0.101",
            "oci_public_ip_ocid": "ocid1.publicip.oc1..fixture",
            "oci_private_ip_ocid": "ocid1.privateip.oc1..fixture",
            "note": "mock allocate; no OCI call made"
        }),
        (Method::POST, "/v1/oci/release") => json!({
            "released": true, "note": "mock release; no OCI call made"
        }),
        (Method::GET, "/v1/oci/vnic/check") => json!({
            "id": "ocid1.vnic.oc1..fixture", "display_name": "edge",
            "skip_source_dest_check": true, "ok": true
        }),
        (Method::GET, "/v1/oci/public-ips") => json!([
            {"id":"ocid1.publicip.oc1..fixture","ip-address":"152.0.0.10",
             "private-ip-id":"ocid1.privateip.oc1..fixture","lifetime":"RESERVED",
             "scope":"REGION","lifecycle-state":"AVAILABLE","display-name":"fixture"}
        ]),
        (Method::POST, "/v1/oci/nsg/add") => json!({ "added": true, "nsg_id": "fixture" }),
        (Method::POST, "/v1/oci/nsg/remove") => json!({ "removed": 1, "nsg_id": "fixture" }),
        _ => {
            if let Some((mapping_id, action)) = mapping_action(path) {
                return handle_mapping_action(&mut store, method, mapping_id, action);
            }
            return Ok((
                StatusCode::NOT_FOUND,
                HeaderMap::new(),
                Bytes::from("mock route not found"),
            ));
        }
    };
    encode_json(response)
}

fn handle_mapping_action(
    store: &mut MockStore,
    method: Method,
    mapping_id: &str,
    action: Option<&str>,
) -> Result<(StatusCode, HeaderMap, Bytes), GatewayError> {
    let Some(index) = store
        .mappings
        .iter()
        .position(|mapping| mapping.id.as_str() == mapping_id)
    else {
        return Ok((
            StatusCode::NOT_FOUND,
            HeaderMap::new(),
            Bytes::from("mapping not found"),
        ));
    };
    match (method, action) {
        (Method::GET, None) => encode_json(
            serde_json::to_value(&store.mappings[index]).map_err(GatewayError::bad_gateway)?,
        ),
        (Method::DELETE, None) => {
            let mapping = store.mappings.remove(index);
            encode_json(serde_json::to_value(mapping).map_err(GatewayError::bad_gateway)?)
        }
        (Method::POST, Some("enable")) => {
            let mapping = &mut store.mappings[index];
            mapping.enabled = true;
            mapping.status = MappingStatus::Pending;
            mapping.updated_at = OffsetDateTime::now_utc();
            encode_json(serde_json::to_value(mapping).map_err(GatewayError::bad_gateway)?)
        }
        (Method::POST, Some("disable")) => {
            let mapping = &mut store.mappings[index];
            mapping.enabled = false;
            mapping.status = MappingStatus::Disabled;
            mapping.updated_at = OffsetDateTime::now_utc();
            encode_json(serde_json::to_value(mapping).map_err(GatewayError::bad_gateway)?)
        }
        _ => Ok((
            StatusCode::METHOD_NOT_ALLOWED,
            HeaderMap::new(),
            Bytes::from("method not allowed"),
        )),
    }
}

fn mapping_action(path: &str) -> Option<(&str, Option<&str>)> {
    let rest = path.strip_prefix("/v1/mappings/")?;
    match rest.split_once('/') {
        Some((id, "enable")) => Some((id, Some("enable"))),
        Some((id, "disable")) => Some((id, Some("disable"))),
        Some(_) => None,
        None => Some((rest, None)),
    }
}

fn encode_json(value: serde_json::Value) -> Result<(StatusCode, HeaderMap, Bytes), GatewayError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    Ok((
        StatusCode::OK,
        headers,
        Bytes::from(serde_json::to_vec(&value).map_err(GatewayError::bad_gateway)?),
    ))
}

fn endpoint(ip: Option<String>, port: Option<u16>) -> String {
    match (ip, port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (Some(ip), None) => ip,
        _ => "-".to_owned(),
    }
}

fn wire_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

impl MockStore {
    fn new() -> Self {
        Self {
            mappings: vec![
                sample_mapping(MappingSeed {
                    id: "map_0a1b2c3d4e5f",
                    name: "mysql",
                    edge_ip: "10.0.0.101",
                    target_ip: "192.168.20.42",
                    mode: MappingMode::PortForwardSnat,
                    protocol: Protocol::Tcp,
                    public_port: Some(13306),
                    target_port: Some(3306),
                    backend: MappingBackend::Nft,
                    status: MappingStatus::Active,
                }),
                sample_mapping(MappingSeed {
                    id: "map_112233445566",
                    name: "home-web",
                    edge_ip: "10.0.0.102",
                    target_ip: "192.168.20.80",
                    mode: MappingMode::OneToOneSnat,
                    protocol: Protocol::All,
                    public_port: None,
                    target_port: None,
                    backend: MappingBackend::Nft,
                    status: MappingStatus::Degraded,
                }),
            ],
            events: vec![
                sample_event(
                    3,
                    EventLevel::Warn,
                    "mapping health degraded",
                    Some("192.168.20.80: timed out"),
                ),
                sample_event(
                    2,
                    EventLevel::Info,
                    "reconcile applied",
                    Some("generation=617"),
                ),
                sample_event(1, EventLevel::Debug, "agent started", None),
            ],
        }
    }
}

fn sample_mapping(seed: MappingSeed) -> Mapping {
    let mut mapping = Mapping::new(
        seed.name,
        Some("203.0.113.10".parse().unwrap()),
        seed.edge_ip.parse().unwrap(),
        seed.target_ip.parse().unwrap(),
    )
    .with_id(MappingId::from_str(seed.id).unwrap());
    mapping.mode = seed.mode;
    mapping.protocol = seed.protocol;
    mapping.public_port = seed.public_port;
    mapping.target_port = seed.target_port;
    mapping.backend = seed.backend;
    mapping.status = seed.status;
    mapping.health_status = Some("sample".to_owned());
    mapping.last_checked_at = Some(OffsetDateTime::now_utc() - Duration::minutes(2));
    mapping
}

fn sample_event(id: i64, level: EventLevel, message: &str, data: Option<&str>) -> Event {
    Event {
        id,
        level,
        message: message.to_owned(),
        data: data.map(str::to_owned),
        created_at: OffsetDateTime::now_utc() - Duration::seconds(id * 45),
    }
}

fn netbird_status() -> NetbirdStatus {
    NetbirdStatus {
        peers: PeerOverview {
            total: 2,
            connected: 1,
            details: vec![
                Peer {
                    fqdn: Some("netbird-routing.bird.home".to_owned()),
                    netbird_ip: Some("100.64.94.84".to_owned()),
                    netbird_ipv6: Some("fd66:a144::2".to_owned()),
                    status: Some("Connected".to_owned()),
                    connection_type: Some("Relayed".to_owned()),
                    networks: vec!["10.10.40.0/24".to_owned()],
                },
                Peer {
                    fqdn: Some("idle.bird.home".to_owned()),
                    netbird_ip: Some("100.64.34.182".to_owned()),
                    netbird_ipv6: Some("fd66:a144::3".to_owned()),
                    status: Some("Idle".to_owned()),
                    connection_type: Some("-".to_owned()),
                    networks: Vec::new(),
                },
            ],
        },
        cli_version: Some("0.73.2".to_owned()),
        daemon_version: Some("0.73.2".to_owned()),
        daemon_status: Some("Connected".to_owned()),
        management: ServiceStatus { connected: true },
        signal: ServiceStatus { connected: true },
        netbird_ip: Some("100.64.65.67/16".to_owned()),
        netbird_ipv6: Some("fd66:a144::1/64".to_owned()),
        uses_kernel_interface: Some(true),
        fqdn: Some("mainvnic.bird.home".to_owned()),
        networks: Vec::new(),
        lazy_connection_enabled: true,
    }
}

fn nft_text() -> &'static str {
    "table ip edge_nat {\n  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n  }\n}\n"
}
