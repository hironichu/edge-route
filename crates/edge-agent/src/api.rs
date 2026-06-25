use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use edge_core::{
    EdgeConfig, EdgeCoreError, Mapping, MappingBackend, MappingId, MappingMode, OciAuthMode,
    Protocol,
};
use edge_nft::{render_nftables, NftRenderConfig};
use edge_oci::OciCli;
use edge_reconcile::{ReconcileOptions, Reconciler};
use edge_store::SqliteStore;
use edge_tailscale::TailscaleCli;
use edge_xdp::XdpConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
struct AppState {
    store: Arc<SqliteStore>,
    config: EdgeConfig,
}

pub fn router(store: SqliteStore, config: EdgeConfig) -> Router {
    let state = AppState {
        store: Arc::new(store),
        config,
    };
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/mappings", get(list_mappings).post(create_mapping))
        .route("/v1/mappings/{id}", get(get_mapping).delete(delete_mapping))
        .route("/v1/mappings/{id}/enable", post(enable_mapping))
        .route("/v1/mappings/{id}/disable", post(disable_mapping))
        .route("/v1/apply/dry-run", post(dry_run_apply))
        .route("/v1/reconcile", post(reconcile))
        .route("/v1/tailscale/status", get(tailscale_status))
        .route("/v1/tailscale/routes", get(tailscale_routes))
        .route("/v1/events", get(events))
        .route("/v1/analytics", get(analytics))
        .route("/v1/topology", get(topology))
        .route("/v1/oci/status", get(oci_status))
        .with_state(state)
}

async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, ApiError> {
    require_auth(&state, &headers)?;
    let mappings = state.store.list_mappings().await?;
    Ok(Json(StatusResponse {
        wan_interface: state.config.wan_interface,
        tailscale_interface: state.config.tailscale_interface,
        mappings: mappings.len(),
        enabled_mappings: mappings.iter().filter(|mapping| mapping.enabled).count(),
    }))
}

async fn list_mappings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Mapping>>, ApiError> {
    require_auth(&state, &headers)?;
    Ok(Json(state.store.list_mappings().await?))
}

async fn create_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateMappingRequest>,
) -> Result<Json<Mapping>, ApiError> {
    require_auth(&state, &headers)?;
    let mut mapping = Mapping::new(
        request.name,
        request.public_ip,
        request.edge_private_ip,
        request.target_ip,
    );
    mapping.public_port = request.public_port;
    mapping.target_port = request.target_port;
    mapping.mode = request.mode.unwrap_or_default();
    mapping.protocol = request.protocol.unwrap_or_default();
    mapping.backend = request.backend.unwrap_or_default();
    state.store.insert_mapping(&mapping).await?;
    Ok(Json(mapping))
}

async fn get_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Mapping>, ApiError> {
    require_auth(&state, &headers)?;
    let id = MappingId::from_str(&id)?;
    Ok(Json(state.store.get_mapping(&id).await?))
}

async fn delete_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Mapping>, ApiError> {
    require_auth(&state, &headers)?;
    let id = MappingId::from_str(&id)?;
    state.store.set_mapping_enabled(&id, false).await?;
    let options = ReconcileOptions {
        nft_output: PathBuf::from("/run/edge-router/generated.nft"),
        dry_run: false,
        apply_nft: true,
        apply_linux: true,
        xdp: XdpConfig::disabled(""),
    };
    if let Err(error) = Reconciler::default()
        .reconcile(&state.store, &state.config, &options)
        .await
    {
        state
            .store
            .record_event(
                edge_core::EventLevel::Error,
                "delete reconcile failed",
                Some(&error.to_string()),
            )
            .await?;
        return Err(ApiError::from_reconcile(error));
    }
    let deleted = state.store.delete_mapping(&id).await?;
    Ok(Json(deleted))
}

async fn enable_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Mapping>, ApiError> {
    require_auth(&state, &headers)?;
    let id = MappingId::from_str(&id)?;
    Ok(Json(state.store.set_mapping_enabled(&id, true).await?))
}

async fn disable_mapping(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Mapping>, ApiError> {
    require_auth(&state, &headers)?;
    let id = MappingId::from_str(&id)?;
    Ok(Json(state.store.set_mapping_enabled(&id, false).await?))
}

async fn dry_run_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, ApiError> {
    require_auth(&state, &headers)?;
    let mappings = state.store.list_mappings().await?;
    Ok(render_nftables(
        &mappings,
        &state.config,
        &NftRenderConfig::default(),
    )?)
}

async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReconcileRequest>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    require_auth(&state, &headers)?;
    let options = ReconcileOptions {
        nft_output: request
            .output
            .unwrap_or_else(|| PathBuf::from("/run/edge-router/generated.nft")),
        dry_run: request.dry_run,
        apply_nft: !request.skip_nft,
        apply_linux: !request.skip_linux,
        xdp: xdp_config(
            request.enable_xdp,
            request.xdp_interface,
            request.xdp_pin_path,
            &state.config,
        ),
    };
    let report = Reconciler::default()
        .reconcile(&state.store, &state.config, &options)
        .await
        .map_err(ApiError::from_reconcile)?;
    Ok(Json(ReconcileResponse {
        generation_id: report.generation_id,
        added_addresses: report.added_addresses,
        removed_addresses: report.removed_addresses,
        xdp_plan_entries: report.xdp_plan_entries,
        nftables_config: if request.include_config {
            Some(report.nftables_config)
        } else {
            None
        },
    }))
}

async fn tailscale_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<edge_tailscale::TailscaleStatus>, ApiError> {
    require_auth(&state, &headers)?;
    Ok(Json(
        TailscaleCli::default()
            .status()
            .await
            .map_err(ApiError::bad_gateway)?,
    ))
}

async fn tailscale_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>, ApiError> {
    require_auth(&state, &headers)?;
    let status = TailscaleCli::default()
        .status()
        .await
        .map_err(ApiError::bad_gateway)?;
    Ok(Json(status.advertised_routes()))
}

async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<edge_core::Event>>, ApiError> {
    require_auth(&state, &headers)?;
    Ok(Json(state.store.list_events(100).await?))
}

async fn analytics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AnalyticsResponse>, ApiError> {
    require_auth(&state, &headers)?;
    let mappings = state.store.list_mappings().await?;
    let events = state.store.list_events(100).await?;
    let problem_mappings = mappings
        .iter()
        .filter(|mapping| matches!(wire_name(&mapping.status).as_str(), "degraded" | "error"))
        .count();
    Ok(Json(AnalyticsResponse {
        mapping_total: mappings.len(),
        mapping_enabled: mappings.iter().filter(|mapping| mapping.enabled).count(),
        mapping_status: count_by(mappings.iter().map(|mapping| wire_name(&mapping.status))),
        mapping_backend: count_by(mappings.iter().map(|mapping| wire_name(&mapping.backend))),
        event_level: count_by(events.iter().map(|event| wire_name(&event.level))),
        problem_mappings,
    }))
}

async fn topology(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TopologyResponse>, ApiError> {
    require_auth(&state, &headers)?;
    let mappings = state.store.list_mappings().await?;
    Ok(Json(TopologyResponse {
        wan_interface: state.config.wan_interface,
        tailscale_interface: state.config.tailscale_interface,
        home_cidrs: state
            .config
            .home_cidrs
            .iter()
            .map(ToString::to_string)
            .collect(),
        flows: mappings.iter().map(topology_flow).collect(),
    }))
}

async fn oci_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OciStatusResponse>, ApiError> {
    require_auth(&state, &headers)?;
    let cli = OciCli::default().version().await;
    let env = OciEnvStatus {
        tenancy_id: std::env::var_os("OCI_TENANCY_ID").is_some(),
        user_id: std::env::var_os("OCI_USER_ID").is_some(),
        fingerprint: std::env::var_os("OCI_FINGERPRINT").is_some(),
        private_key_path: std::env::var_os("OCI_PRIVATE_KEY_PATH").is_some(),
    };
    let api_key_ready = env.tenancy_id && env.user_id && env.fingerprint && env.private_key_path;
    Ok(Json(OciStatusResponse {
        auth_mode: state.config.oci_auth,
        region: state.config.oci_region,
        compartment_id_configured: state.config.oci_compartment_id.is_some(),
        vnic_id_configured: state.config.oci_vnic_id.is_some(),
        subnet_id_configured: state.config.oci_subnet_id.is_some(),
        nsg_count: state.config.oci_nsg_ids.len(),
        api_key_env_ready: api_key_ready,
        env,
        cli_available: cli.is_ok(),
        cli_version: cli.ok().map(|output| output.stdout.trim().to_owned()),
    }))
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    wan_interface: String,
    tailscale_interface: String,
    mappings: usize,
    enabled_mappings: usize,
}

#[derive(Debug, Serialize)]
struct AnalyticsResponse {
    mapping_total: usize,
    mapping_enabled: usize,
    mapping_status: BTreeMap<String, usize>,
    mapping_backend: BTreeMap<String, usize>,
    event_level: BTreeMap<String, usize>,
    problem_mappings: usize,
}

#[derive(Debug, Serialize)]
struct TopologyResponse {
    wan_interface: String,
    tailscale_interface: String,
    home_cidrs: Vec<String>,
    flows: Vec<TopologyFlow>,
}

#[derive(Debug, Serialize)]
struct TopologyFlow {
    id: String,
    name: String,
    public_endpoint: String,
    edge_private_ip: String,
    target_endpoint: String,
    protocol: String,
    mode: String,
    backend: String,
    status: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct OciStatusResponse {
    auth_mode: OciAuthMode,
    region: Option<String>,
    compartment_id_configured: bool,
    vnic_id_configured: bool,
    subnet_id_configured: bool,
    nsg_count: usize,
    api_key_env_ready: bool,
    env: OciEnvStatus,
    cli_available: bool,
    cli_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct OciEnvStatus {
    tenancy_id: bool,
    user_id: bool,
    fingerprint: bool,
    private_key_path: bool,
}

fn topology_flow(mapping: &Mapping) -> TopologyFlow {
    TopologyFlow {
        id: mapping.id.to_string(),
        name: mapping.name.clone(),
        public_endpoint: endpoint(
            mapping.public_ip.map(|ip| ip.to_string()),
            mapping.public_port,
        ),
        edge_private_ip: mapping.edge_private_ip.to_string(),
        target_endpoint: endpoint(Some(mapping.target_ip.to_string()), mapping.target_port),
        protocol: wire_name(&mapping.protocol),
        mode: wire_name(&mapping.mode),
        backend: wire_name(&mapping.backend),
        status: wire_name(&mapping.status),
        enabled: mapping.enabled,
    }
}

fn endpoint(ip: Option<String>, port: Option<u16>) -> String {
    match (ip, port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (Some(ip), None) => ip,
        _ => "-".to_owned(),
    }
}

fn count_by(values: impl Iterator<Item = String>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

fn wire_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

#[derive(Debug, Deserialize)]
struct CreateMappingRequest {
    name: String,
    public_ip: Option<Ipv4Addr>,
    edge_private_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    public_port: Option<u16>,
    target_port: Option<u16>,
    mode: Option<MappingMode>,
    protocol: Option<Protocol>,
    backend: Option<MappingBackend>,
}

#[derive(Debug, Deserialize)]
struct ReconcileRequest {
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    skip_linux: bool,
    #[serde(default)]
    skip_nft: bool,
    #[serde(default)]
    include_config: bool,
    #[serde(default)]
    enable_xdp: bool,
    xdp_interface: Option<String>,
    xdp_pin_path: Option<PathBuf>,
    output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct ReconcileResponse {
    generation_id: Option<i64>,
    added_addresses: Vec<String>,
    removed_addresses: Vec<String>,
    xdp_plan_entries: usize,
    nftables_config: Option<String>,
}

fn xdp_config(
    enabled: bool,
    interface: Option<String>,
    pin_path: Option<PathBuf>,
    config: &EdgeConfig,
) -> XdpConfig {
    let interface = interface.unwrap_or_else(|| config.wan_interface.clone());
    let pin_path = pin_path.unwrap_or_else(|| PathBuf::from("/sys/fs/bpf/edgeroute"));
    if enabled {
        XdpConfig::enabled(interface, pin_path)
    } else {
        XdpConfig::disabled(interface)
    }
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl From<EdgeCoreError> for ApiError {
    fn from(error: EdgeCoreError) -> Self {
        let status = match error {
            EdgeCoreError::NotFound(_) => StatusCode::NOT_FOUND,
            EdgeCoreError::Validation(_)
            | EdgeCoreError::DuplicatePublicIp(_)
            | EdgeCoreError::DuplicateEdgePrivateIp(_)
            | EdgeCoreError::DuplicateTargetIp(_)
            | EdgeCoreError::DuplicateMappingId(_) => StatusCode::BAD_REQUEST,
            EdgeCoreError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "missing or invalid bearer token".to_owned(),
        }
    }

    fn bad_gateway(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: error.to_string(),
        }
    }

    fn from_reconcile(error: edge_reconcile::ReconcileError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(expected) = state.config.api_token.as_deref() else {
        return Ok(());
    };
    let Some(actual) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(ApiError::unauthorized());
    };
    if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(ApiError::unauthorized())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..max {
        let a = left.get(idx).copied().unwrap_or(0);
        let b = right.get(idx).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn compares_tokens_constant_time_style() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secrex"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
    }
}
