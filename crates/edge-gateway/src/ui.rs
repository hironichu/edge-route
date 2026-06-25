use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{Html, IntoResponse};
use axum::Form;
use edge_core::{Event, Mapping};
use edge_tailscale::TailscaleStatus;
use maud::{html, Markup};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

use crate::{agent, AppState, GatewayError};

#[derive(Debug, Deserialize)]
pub struct CreateMappingForm {
    name: String,
    public_ip: Option<String>,
    edge_private_ip: String,
    target_ip: String,
    public_port: Option<String>,
    target_port: Option<String>,
    mode: String,
    protocol: String,
    backend: String,
}

#[derive(Debug, Deserialize)]
pub struct ReconcileForm {
    dry_run: Option<String>,
    skip_linux: Option<String>,
    skip_nft: Option<String>,
    include_config: Option<String>,
    enable_xdp: Option<String>,
    xdp_interface: Option<String>,
    xdp_pin_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    wan_interface: String,
    tailscale_interface: String,
    mappings: usize,
    enabled_mappings: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReconcileResponse {
    generation_id: Option<i64>,
    added_addresses: Vec<String>,
    removed_addresses: Vec<String>,
    xdp_plan_entries: usize,
    nftables_config: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TopologyResponse {
    wan_interface: String,
    tailscale_interface: String,
    home_cidrs: Vec<String>,
    flows: Vec<TopologyFlow>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
struct OciStatusResponse {
    auth_mode: String,
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

#[derive(Debug, Deserialize)]
struct OciEnvStatus {
    tenancy_id: bool,
    user_id: bool,
    fingerprint: bool,
    private_key_path: bool,
}

#[derive(Debug, Deserialize)]
pub struct PingForm {
    target: String,
}

#[derive(Debug, Deserialize)]
pub struct PortTestForm {
    target: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
pub struct TcpDumpForm {
    interface: String,
    filter: Option<String>,
    packets: Option<u16>,
}

#[derive(Debug)]
struct ToolResult {
    title: &'static str,
    ok: bool,
    body: String,
}

pub async fn dashboard(State(state): State<AppState>) -> impl IntoResponse {
    render_result(dashboard_markup(&state).await)
}

pub async fn mappings(State(state): State<AppState>) -> impl IntoResponse {
    render_result(mappings_markup(&state).await)
}

pub async fn create_mapping(
    State(state): State<AppState>,
    Form(form): Form<CreateMappingForm>,
) -> impl IntoResponse {
    render_result(
        async {
            let body = json!({
                "name": form.name,
                "public_ip": clean_opt(form.public_ip),
                "edge_private_ip": form.edge_private_ip.trim(),
                "target_ip": form.target_ip.trim(),
                "public_port": clean_port(form.public_port)?,
                "target_port": clean_port(form.target_port)?,
                "mode": form.mode,
                "protocol": form.protocol,
                "backend": form.backend,
            });
            let _: Mapping = agent::post_json(&state, "/v1/mappings", &body).await?;
            mappings_markup(&state).await
        }
        .await,
    )
}

pub async fn enable_mapping(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    render_result(
        async {
            let _: Mapping =
                agent::post_empty_json(&state, &format!("/v1/mappings/{id}/enable")).await?;
            mappings_markup(&state).await
        }
        .await,
    )
}

pub async fn disable_mapping(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    render_result(
        async {
            let _: Mapping =
                agent::post_empty_json(&state, &format!("/v1/mappings/{id}/disable")).await?;
            mappings_markup(&state).await
        }
        .await,
    )
}

pub async fn delete_mapping(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    render_result(
        async {
            let _: Mapping = agent::delete_json(&state, &format!("/v1/mappings/{id}")).await?;
            mappings_markup(&state).await
        }
        .await,
    )
}

pub async fn reconcile(State(state): State<AppState>) -> impl IntoResponse {
    render_result(reconcile_markup(&state, None, None).await)
}

pub async fn run_reconcile(
    State(state): State<AppState>,
    Form(form): Form<ReconcileForm>,
) -> impl IntoResponse {
    render_result(
        async {
            let body = json!({
                "dry_run": form.dry_run.is_some(),
                "skip_linux": form.skip_linux.is_some(),
                "skip_nft": form.skip_nft.is_some(),
                "include_config": form.include_config.is_some(),
                "enable_xdp": form.enable_xdp.is_some(),
                "xdp_interface": form.xdp_interface.filter(|value| !value.trim().is_empty()),
                "xdp_pin_path": form.xdp_pin_path.and_then(|value| clean_opt(Some(value))).map(PathBuf::from),
            });
            let report: ReconcileResponse =
                agent::post_json(&state, "/v1/reconcile", &body).await?;
            reconcile_markup(&state, Some(report), None).await
        }
        .await,
    )
}

pub async fn dry_run_ruleset(State(state): State<AppState>) -> impl IntoResponse {
    render_result(
        async {
            let rules = agent::post_text(&state, "/v1/apply/dry-run").await?;
            reconcile_markup(&state, None, Some(rules)).await
        }
        .await,
    )
}

pub async fn tools(State(state): State<AppState>) -> impl IntoResponse {
    render_result(tools_markup(&state, None, "validation").await)
}

pub async fn topology(State(state): State<AppState>) -> impl IntoResponse {
    render_result(topology_markup(&state).await)
}

pub async fn oracle(State(state): State<AppState>) -> impl IntoResponse {
    render_result(oracle_markup(&state).await)
}

pub async fn tools_dry_run(State(state): State<AppState>) -> impl IntoResponse {
    render_result(
        async {
            let rules = agent::post_text(&state, "/v1/apply/dry-run").await?;
            tools_markup(
                &state,
                Some(ToolResult {
                    title: "Ruleset Dry Run",
                    ok: true,
                    body: rules,
                }),
                "validation",
            )
            .await
        }
        .await,
    )
}

pub async fn tools_reconcile_check(State(state): State<AppState>) -> impl IntoResponse {
    render_result(
        async {
            let report: ReconcileResponse = agent::post_json(
                &state,
                "/v1/reconcile",
                &json!({
                    "dry_run": true,
                    "skip_linux": true,
                    "skip_nft": true,
                    "include_config": true,
                    "enable_xdp": true,
                }),
            )
            .await?;
            tools_markup(
                &state,
                Some(ToolResult {
                    title: "Reconcile Validation",
                    ok: true,
                    body: serde_json::to_string_pretty(&report).map_err(GatewayError::internal)?,
                }),
                "validation",
            )
            .await
        }
        .await,
    )
}

pub async fn ping_tool(
    State(state): State<AppState>,
    Form(form): Form<PingForm>,
) -> impl IntoResponse {
    render_result(
        async {
            let target = form.target.trim();
            let _: IpAddr = target.parse().map_err(|_| {
                GatewayError::bad_gateway("ping target must be an IPv4 or IPv6 address")
            })?;
            let output = timeout(
                Duration::from_secs(8),
                Command::new("ping")
                    .arg("-c")
                    .arg("3")
                    .arg("-W")
                    .arg("2")
                    .arg(target)
                    .output(),
            )
            .await
            .map_err(|_| GatewayError::bad_gateway("ping timed out"))?
            .map_err(GatewayError::bad_gateway)?;
            let mut body = String::from_utf8_lossy(&output.stdout).into_owned();
            if !output.stderr.is_empty() {
                body.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            tools_markup(
                &state,
                Some(ToolResult {
                    title: "Ping Result",
                    ok: output.status.success(),
                    body,
                }),
                "reachability",
            )
            .await
        }
        .await,
    )
}

pub async fn port_test_tool(
    State(state): State<AppState>,
    Form(form): Form<PortTestForm>,
) -> impl IntoResponse {
    render_result(
        async {
            let target = form.target.trim();
            let ip: IpAddr = target.parse().map_err(|_| {
                GatewayError::bad_gateway("port test target must be an IPv4 or IPv6 address")
            })?;
            if form.port == 0 {
                return Err(GatewayError::bad_gateway(
                    "port must be between 1 and 65535",
                ));
            }
            let address = (ip, form.port);
            let started = std::time::Instant::now();
            let result = timeout(Duration::from_secs(5), TcpStream::connect(address)).await;
            let elapsed_ms = started.elapsed().as_millis();
            let (ok, body) = match result {
                Ok(Ok(_stream)) => (
                    true,
                    format!(
                        "TCP connect to {ip}:{} succeeded in {elapsed_ms} ms",
                        form.port
                    ),
                ),
                Ok(Err(error)) => (
                    false,
                    format!(
                        "TCP connect to {ip}:{} failed after {elapsed_ms} ms\n{error}",
                        form.port
                    ),
                ),
                Err(_) => (
                    false,
                    format!("TCP connect to {ip}:{} timed out after 5000 ms", form.port),
                ),
            };
            tools_markup(
                &state,
                Some(ToolResult {
                    title: "Port Test Result",
                    ok,
                    body,
                }),
                "reachability",
            )
            .await
        }
        .await,
    )
}

pub async fn tcpdump_tool(
    State(state): State<AppState>,
    Form(form): Form<TcpDumpForm>,
) -> impl IntoResponse {
    render_result(
        async {
            let interface = clean_interface(&form.interface)?;
            let packets = form.packets.unwrap_or(25).clamp(1, 200);
            let filter = clean_tcpdump_filter(form.filter.as_deref())?;
            let mut command = Command::new("tcpdump");
            command
                .arg("-i")
                .arg(interface)
                .arg("-nn")
                .arg("-tttt")
                .arg("-vv")
                .arg("-c")
                .arg(packets.to_string());
            command.args(&filter);
            let output = timeout(Duration::from_secs(18), command.output())
                .await
                .map_err(|_| GatewayError::bad_gateway("tcpdump capture timed out"))?
                .map_err(GatewayError::bad_gateway)?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let body = tcpdump_report(&stdout, &stderr, packets, &filter);
            tools_markup(
                &state,
                Some(ToolResult {
                    title: "TCP Dump Analysis",
                    ok: output.status.success(),
                    body,
                }),
                "capture",
            )
            .await
        }
        .await,
    )
}

pub async fn tailscale(State(state): State<AppState>) -> impl IntoResponse {
    render_result(tailscale_markup(&state).await)
}

pub async fn events(State(state): State<AppState>) -> impl IntoResponse {
    render_result(events_markup(&state).await)
}

pub async fn download_logs(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, GatewayError> {
    let events: Vec<Event> = agent::get_json(&state, "/v1/events").await?;
    Ok((
        [
            (CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"edgeroute-events.log\"",
            ),
        ],
        raw_log_lines(&events),
    ))
}

async fn dashboard_markup(state: &AppState) -> Result<Markup, GatewayError> {
    let status: StatusResponse = agent::get_json(state, "/v1/status").await?;
    let mappings: Vec<Mapping> = agent::get_json(state, "/v1/mappings")
        .await
        .unwrap_or_default();
    let events: Vec<Event> = agent::get_json(state, "/v1/events")
        .await
        .unwrap_or_default();
    let tailscale: Option<TailscaleStatus> =
        agent::get_json(state, "/v1/tailscale/status").await.ok();
    let routes: Vec<String> = agent::get_json(state, "/v1/tailscale/routes")
        .await
        .unwrap_or_default();
    let mapping_status_counts = count_by(mappings.iter().map(mapping_status));
    let backends = count_by(mappings.iter().map(|mapping| wire_name(&mapping.backend)));
    let online_peers = tailscale
        .as_ref()
        .map(|status| {
            status
                .peers
                .values()
                .filter(|peer| peer.online == Some(true))
                .count()
        })
        .unwrap_or_default();
    let offline_peers = tailscale
        .as_ref()
        .map(|status| {
            status
                .peers
                .values()
                .filter(|peer| peer.online == Some(false))
                .count()
        })
        .unwrap_or_default();
    let mut alerts = Vec::new();
    let bad_mappings = mappings
        .iter()
        .filter(|mapping| matches!(mapping_status(mapping).as_str(), "degraded" | "error"))
        .count();
    if bad_mappings > 0 {
        alerts.push(format!("{bad_mappings} mapping(s) degraded or failed"));
    }
    if events
        .iter()
        .any(|event| matches!(wire_name(&event.level).as_str(), "warn" | "error"))
    {
        alerts.push("warning/error events recorded".to_owned());
    }
    if offline_peers > 0 {
        alerts.push(format!("{offline_peers} Tailscale peer(s) offline"));
    }
    if tailscale
        .as_ref()
        .and_then(|status| status.backend_state.as_deref())
        .is_some_and(|state| state != "Running")
    {
        alerts.push("Tailscale backend is not Running".to_owned());
    }
    Ok(html! {
        (page_head("Dashboard", "Control plane state", html! {
            button class="btn" hx-get="/ui/dashboard" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        div class="summary-row" {
            (summary_item("Mappings", &status.mappings.to_string(), "total configured"))
            (summary_item("Enabled", &status.enabled_mappings.to_string(), "active in store"))
            (summary_item("WAN", &status.wan_interface, "public interface"))
            (summary_item("Alerts", &alerts.len().to_string(), "live derived"))
        }
        div class="dashboard-layout" {
            section class="console-section health-section" {
                header { h2 { "Router Health" } span class="muted" { "live agent snapshot" } }
                div class="status-strip vertical" {
                    div { span class="label" { "Tailscale" } strong { (tailscale.as_ref().and_then(|t| t.backend_state.as_deref()).unwrap_or("unknown")) } small { (&status.tailscale_interface) } }
                    div { span class="label" { "Advertised Routes" } strong { (routes.len()) } small { (join_or_dash(&routes)) } }
                    div { span class="label" { "Peers Online" } strong { (online_peers) "/" (online_peers + offline_peers) } small { "from tailscale status" } }
                    div { span class="label" { "Rule Coverage" } strong { (status.enabled_mappings) "/" (status.mappings) } small { "enabled mappings" } }
                }
            }
            section class="console-section alert-section" {
                header { h2 { "Alerts" } a href="/ui/logs" hx-get="/ui/logs" hx-target="#view" hx-swap="innerHTML transition:true" { "Logs" } }
                div class="card-body" {
                    @if alerts.is_empty() {
                        div class="ok-block" { strong { "Nominal" } span { "No live health alerts from available APIs." } }
                    } @else {
                        ul class="alert-list" {
                            @for alert in &alerts {
                                li { (status_pill("warn")) span { (alert) } }
                            }
                        }
                    }
                }
            }
            section class="console-section chart-card" {
                header { h2 { "Mapping Status" } }
                div class="card-body" { (bar_chart(&mapping_status_counts)) }
            }
            section class="console-section chart-card" {
                header { h2 { "Routing Backends" } }
                div class="card-body" { (bar_chart(&backends)) }
            }
            section class="console-section chart-card" {
                header { h2 { "Tailnet Peer State" } }
                div class="card-body" { (bar_chart(&BTreeMap::from([
                    ("online".to_owned(), online_peers),
                    ("offline".to_owned(), offline_peers),
                ]))) }
            }
            section class="console-section logs-preview" {
                header { h2 { "Recent Logs" } a href="/ui/logs" hx-get="/ui/logs" hx-target="#view" hx-swap="innerHTML transition:true" { "View all" } }
                (events_list(&events.iter().take(8).cloned().collect::<Vec<_>>()))
            }
            section class="console-section ops-actions" {
                header { h2 { "Operations" } }
                div class="card-body" {
                    div class="tool-links" {
                        a class="btn" href="/tools" hx-get="/ui/tools" hx-target="#view" hx-swap="innerHTML transition:true" hx-push-url="/tools" { "Diagnostics" }
                        a class="btn" href="/mappings" hx-get="/ui/mappings" hx-target="#view" hx-swap="innerHTML transition:true" hx-push-url="/mappings" { "Mappings" }
                        a class="btn" href="/tailscale" hx-get="/ui/tailscale" hx-target="#view" hx-swap="innerHTML transition:true" hx-push-url="/tailscale" { "Tailscale" }
                        a class="btn" href="/reconcile" hx-get="/ui/reconcile" hx-target="#view" hx-swap="innerHTML transition:true" hx-push-url="/reconcile" { "Reconcile" }
                    }
                }
            }
        }
    })
}

async fn mappings_markup(state: &AppState) -> Result<Markup, GatewayError> {
    let mappings: Vec<Mapping> = agent::get_json(state, "/v1/mappings").await?;
    let topology: Option<TopologyResponse> = agent::get_json(state, "/v1/topology").await.ok();
    let flows = topology
        .as_ref()
        .map(|topology| topology.flows.as_slice())
        .unwrap_or_default();
    Ok(html! {
        (page_head("Mappings", "NAT rules", html! {
            button class="primary" type="button" data-open-dialog="new-mapping-dialog" { "New Mapping" }
            button class="btn" type="button" data-bulk-action disabled { "Bulk Actions" }
            button class="btn" type="button" data-inspect-selected disabled { "Inspect" }
            button class="btn" hx-get="/ui/mappings" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        section class="console-section" {
            div class="section-toolbar" {
                div {
                    h2 { "Rules" }
                    p class="muted" { (mappings.len()) " total, " (mappings.iter().filter(|mapping| mapping.enabled).count()) " enabled" }
                }
                div class="row" {
                    span class="selection-count" data-selection-count { "0 selected" }
                }
            }
            @if mappings.is_empty() {
                (empty("No mappings configured."))
            } @else {
                div class="table-wrap mappings-wrap" {
                    table class="mappings-table" {
                        colgroup {
                            col class="col-select";
                            col class="col-name";
                            col class="col-endpoint";
                            col class="col-ip";
                            col class="col-endpoint";
                            col class="col-small";
                            col class="col-mode";
                            col class="col-small";
                            col class="col-status";
                            col class="col-actions";
                        }
                        thead { tr {
                            th { input type="checkbox" data-select-all aria-label="Select all mappings"; }
                            th { "Name" } th { "Public" } th { "Edge" } th { "Target" }
                            th { "Protocol" } th { "Mode" } th { "Backend" } th { "Status" } th { "Actions" }
                        }}
                        tbody {
                            @for mapping in &mappings {
                                @let dialog_id = inspect_dialog_id(mapping);
                                tr {
                                    td { input type="checkbox" data-row-select data-dialog-id=(dialog_id.as_str()) aria-label=(format!("Select {}", mapping.name)); }
                                    td { strong class="clip" { (&mapping.name) } span class="sub mono clip" { (mapping.id.as_str()) } }
                                    td class="mono clip" title=(endpoint(mapping.public_ip.map(|ip| ip.to_string()), mapping.public_port)) { (endpoint(mapping.public_ip.map(|ip| ip.to_string()), mapping.public_port)) }
                                    td class="mono" { (mapping.edge_private_ip) }
                                    td class="mono clip" title=(endpoint(Some(mapping.target_ip.to_string()), mapping.target_port)) { (endpoint(Some(mapping.target_ip.to_string()), mapping.target_port)) }
                                    td { (wire_name(&mapping.protocol)) }
                                    td { (wire_name(&mapping.mode)) }
                                    td { (wire_name(&mapping.backend)) }
                                    td { (status_pill(&mapping_status(mapping))) @if let Some(err) = &mapping.last_error { span class="sub err clip" title=(err) { (err) } } }
                                    td class="actions-cell" {
                                        div class="row nowrap" {
                                            button class="btn" type="button" title=(format!("Inspect {}", mapping.name)) data-open-dialog=(dialog_id.as_str()) { "Inspect" }
                                            @if mapping.enabled {
                                                button class="btn" hx-post=(format!("/ui/mappings/{}/disable", mapping.id.as_str())) hx-target="#view" hx-swap="innerHTML transition:true" { "Disable" }
                                            } @else {
                                                button class="btn" hx-post=(format!("/ui/mappings/{}/enable", mapping.id.as_str())) hx-target="#view" hx-swap="innerHTML transition:true" { "Enable" }
                                            }
                                            button class="btn danger" hx-delete=(format!("/ui/mappings/{}", mapping.id.as_str())) hx-target="#view" hx-swap="innerHTML transition:true" hx-confirm=(format!("Delete mapping {}?", mapping.name)) { "Delete" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        @if let Some(topology) = &topology {
            section class="console-section section-spaced" {
                header {
                    h2 { "Path" }
                    span class="muted" { (&topology.wan_interface) " -> " (&topology.tailscale_interface) }
                }
                (binding_diagrams(&topology.flows))
            }
        }
        @for mapping in &mappings {
            (inspect_mapping_dialog(mapping, flows.iter().find(|flow| flow.id == mapping.id.as_str())))
        }
        (new_mapping_dialog())
    })
}

async fn reconcile_markup(
    _state: &AppState,
    report: Option<ReconcileResponse>,
    ruleset: Option<String>,
) -> Result<Markup, GatewayError> {
    Ok(html! {
        (page_head("Reconcile", "Validate, render, and apply desired state", html! {}))
        div class="grid two" {
            section class="card" {
                header { h2 { "Reconcile Options" } }
                div class="card-body" {
                    form hx-post="/ui/reconcile" hx-target="#view" hx-swap="innerHTML transition:true" {
                        label class="checkline" { input type="checkbox" name="dry_run" checked; span { "Dry run" small { " no live apply" } } }
                        label class="checkline" { input type="checkbox" name="include_config" checked; span { "Include nftables config" } }
                        label class="checkline" { input type="checkbox" name="skip_linux"; span { "Skip Linux address changes" } }
                        label class="checkline" { input type="checkbox" name="skip_nft"; span { "Skip nft apply" } }
                        label class="checkline" { input type="checkbox" name="enable_xdp"; span { "Enable XDP planning" } }
                        label class="field" { span { "XDP interface" } input name="xdp_interface" placeholder="ens3"; }
                        label class="field" { span { "XDP pin path" } input name="xdp_pin_path" placeholder="/sys/fs/bpf/edgeroute"; }
                        div class="row" {
                            button class="primary" type="submit" { "Run Reconcile" }
                            button class="btn" type="button" hx-post="/ui/reconcile/dry-run" hx-target="#view" hx-swap="innerHTML transition:true" { "Render Ruleset" }
                        }
                    }
                }
            }
            section class="card" {
                header { h2 { "Result" } }
                div class="card-body" {
                    @if let Some(report) = report {
                        dl class="facts" {
                            dt { "Generation" } dd { (report.generation_id.map(|id| id.to_string()).unwrap_or_else(|| "dry-run".to_owned())) }
                            dt { "Added addresses" } dd { (join_or_dash(&report.added_addresses)) }
                            dt { "Removed addresses" } dd { (join_or_dash(&report.removed_addresses)) }
                            dt { "XDP plan entries" } dd { (report.xdp_plan_entries) }
                        }
                        @if let Some(config) = report.nftables_config {
                            pre class="code" { (config) }
                        }
                    } @else if let Some(ruleset) = ruleset {
                        pre class="code" { (ruleset) }
                    } @else {
                        (empty("Run reconcile or render a dry-run ruleset."))
                    }
                }
            }
        }
    })
}

async fn topology_markup(state: &AppState) -> Result<Markup, GatewayError> {
    let topology: TopologyResponse = agent::get_json(state, "/v1/topology").await?;
    Ok(html! {
        (page_head("Topology", "Live bind paths and routing shape", html! {
            button class="btn" hx-get="/ui/topology" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        div class="summary-row" {
            (summary_item("WAN", &topology.wan_interface, "public side"))
            (summary_item("Tailnet", &topology.tailscale_interface, "private side"))
            (summary_item("Home CIDRs", &topology.home_cidrs.len().to_string(), &join_or_dash(&topology.home_cidrs)))
            (summary_item("Binds", &topology.flows.len().to_string(), "configured flows"))
        }
        section class="console-section section-spaced" {
            header { h2 { "Binding Diagrams" } span class="muted" { "public edge to private target" } }
            (binding_diagrams(&topology.flows))
        }
    })
}

async fn oracle_markup(state: &AppState) -> Result<Markup, GatewayError> {
    let oci: OciStatusResponse = agent::get_json(state, "/v1/oci/status").await?;
    let needs_api_key = oci.auth_mode == "api_key" && !oci.api_key_env_ready;
    Ok(html! {
        (page_head("Oracle", "OCI CLI and allocation readiness", html! {
            button class="btn" hx-get="/ui/oracle" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        div class="summary-row" {
            (summary_item("Auth Mode", &oci.auth_mode, "edge config"))
            (summary_item("Region", oci.region.as_deref().unwrap_or("-"), "OCI region"))
            (summary_item("OCI CLI", if oci.cli_available { "available" } else { "missing/timeout" }, oci.cli_version.as_deref().unwrap_or("no version")))
            (summary_item("API Key Env", if oci.api_key_env_ready { "ready" } else { "missing" }, "for api_key mode"))
        }
        section class="console-section section-spaced" {
            header { h2 { "Configuration Readiness" } }
            div class="split-layout oracle-split" {
                div {
                    h3 { "Edge Config" }
                    dl class="facts" {
                        dt { "Compartment" } dd { (bool_text(oci.compartment_id_configured)) }
                        dt { "VNIC" } dd { (bool_text(oci.vnic_id_configured)) }
                        dt { "Subnet" } dd { (bool_text(oci.subnet_id_configured)) }
                        dt { "NSGs" } dd { (oci.nsg_count) }
                    }
                }
                div {
                    h3 { "API Key Env" }
                    dl class="facts" {
                        dt { "OCI_TENANCY_ID" } dd { (bool_text(oci.env.tenancy_id)) }
                        dt { "OCI_USER_ID" } dd { (bool_text(oci.env.user_id)) }
                        dt { "OCI_FINGERPRINT" } dd { (bool_text(oci.env.fingerprint)) }
                        dt { "OCI_PRIVATE_KEY_PATH" } dd { (bool_text(oci.env.private_key_path)) }
                    }
                }
                div {
                    h3 { "What This Means" }
                    @if needs_api_key {
                        p class="warn-text" { "api_key mode is selected but required env vars are missing." }
                    } @else if oci.auth_mode == "instance_principal" {
                        p class="muted" { "Instance principal works only when OCI CLI is configured to use it, usually on an OCI instance with proper dynamic-group policy." }
                    } @else {
                        p class="muted" { "OCI API key environment looks ready for direct API mode." }
                    }
                    pre class="code tight" { "oci setup config\n# or for an OCI instance:\noci --auth instance_principal iam region list" }
                }
            }
        }
    })
}

async fn tools_markup(
    state: &AppState,
    result: Option<ToolResult>,
    active_tab: &str,
) -> Result<Markup, GatewayError> {
    let status: StatusResponse = agent::get_json(state, "/v1/status").await?;
    let mappings: Vec<Mapping> = agent::get_json(state, "/v1/mappings")
        .await
        .unwrap_or_default();
    let routes: Vec<String> = agent::get_json(state, "/v1/tailscale/routes")
        .await
        .unwrap_or_default();
    Ok(html! {
        (page_head("Tools", "Validate routing, reachability, and config state", html! {
            button class="btn" hx-get="/ui/tools" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        div class="summary-row" {
            (summary_item("WAN", &status.wan_interface, "agent config"))
            (summary_item("Tailnet IF", &status.tailscale_interface, "agent config"))
            (summary_item("Routes", &routes.len().to_string(), "tailscale advertised"))
            (summary_item("Mappings", &mappings.len().to_string(), "loaded from agent"))
        }
        div class="tools-layout" data-tabs-scope {
            section class="console-section tool-console" {
                header {
                    h2 { "Toolbox" }
                    span class="muted" { "select one diagnostic mode" }
                }
                div class="sub-menu" role="tablist" aria-label="Tool categories" {
                    button type="button" role="tab" class=(tab_button_class(active_tab, "validation")) aria-selected=(is_active_tab(active_tab, "validation")) data-tab-target="validation" { "Validation" }
                    button type="button" role="tab" class=(tab_button_class(active_tab, "reachability")) aria-selected=(is_active_tab(active_tab, "reachability")) data-tab-target="reachability" { "Reachability" }
                    button type="button" role="tab" class=(tab_button_class(active_tab, "capture")) aria-selected=(is_active_tab(active_tab, "capture")) data-tab-target="capture" { "Packet Capture" }
                    button type="button" role="tab" class=(tab_button_class(active_tab, "inputs")) aria-selected=(is_active_tab(active_tab, "inputs")) data-tab-target="inputs" { "Route Inputs" }
                }
                div class="tool-panels" {
                    section class=(tab_panel_class(active_tab, "validation")) data-tab-panel="validation" {
                        h2 { "Validation" }
                        p class="muted" { "Check generated firewall state before anything is applied." }
                        div class="tool-actions-block" {
                            button class="primary" hx-post="/ui/tools/dry-run" hx-target="#view" hx-swap="innerHTML transition:true" { "Validate Ruleset" }
                            button class="btn" hx-post="/ui/tools/reconcile-check" hx-target="#view" hx-swap="innerHTML transition:true" { "Run Dry Reconcile" }
                        }
                    }
                    section class=(tab_panel_class(active_tab, "reachability")) data-tab-panel="reachability" {
                        h2 { "Reachability" }
                        div class="tool-form-grid" {
                            form hx-post="/ui/tools/ping" hx-target="#view" hx-swap="innerHTML transition:true" {
                                h3 { "ICMP Ping" }
                                label class="field" { span { "Target IP" } input name="target" required placeholder="100.64.0.1"; }
                                button class="primary" type="submit" { "Ping Target" }
                            }
                            form hx-post="/ui/tools/port-test" hx-target="#view" hx-swap="innerHTML transition:true" {
                                h3 { "TCP Port" }
                                div class="tool-form-row" {
                                    label class="field" { span { "Target IP" } input name="target" required placeholder="192.168.20.80"; }
                                    label class="field port-field" { span { "Port" } input name="port" type="number" min="1" max="65535" required placeholder="443"; }
                                }
                                button class="btn" type="submit" { "Test TCP Port" }
                            }
                        }
                    }
                    section class=(tab_panel_class(active_tab, "capture")) data-tab-panel="capture" {
                        h2 { "Packet Capture" }
                        form hx-post="/ui/tools/tcpdump" hx-target="#view" hx-swap="innerHTML transition:true" {
                            div class="tool-form-row" {
                                label class="field" { span { "Interface" } input name="interface" required value=(&status.wan_interface) placeholder="ens3"; }
                                label class="field port-field" { span { "Packets" } input name="packets" type="number" min="1" max="200" value="25"; }
                            }
                            label class="field" { span { "BPF filter" } input name="filter" placeholder="host 192.168.20.80 and tcp"; }
                            button class="primary" type="submit" { "Run TCP Dump" }
                        }
                    }
                    section class=(tab_panel_class(active_tab, "inputs")) data-tab-panel="inputs" {
                        h2 { "Route Inputs" }
                        dl class="facts compact" {
                            dt { "Advertised" } dd class="mono" { (join_or_dash(&routes)) }
                            dt { "Enabled" } dd { (mappings.iter().filter(|mapping| mapping.enabled).count()) }
                            dt { "Problems" } dd { (mappings.iter().filter(|mapping| matches!(mapping_status(mapping).as_str(), "degraded" | "error")).count()) }
                            dt { "WAN" } dd class="mono" { (&status.wan_interface) }
                            dt { "Tailnet" } dd class="mono" { (&status.tailscale_interface) }
                        }
                    }
                }
            }
            section class="console-section result-pane" {
                header {
                    h2 { "Result" }
                    @if let Some(result) = &result {
                        (status_pill(if result.ok { "active" } else { "error" }))
                    }
                }
                div class="card-body" {
                    @if let Some(result) = result {
                        h3 { (result.title) }
                        pre class="code" { (result.body) }
                    } @else {
                        (empty("Run a validation or diagnostic tool."))
                    }
                }
            }
        }
    })
}

async fn tailscale_markup(state: &AppState) -> Result<Markup, GatewayError> {
    let status: TailscaleStatus = agent::get_json(state, "/v1/tailscale/status").await?;
    let routes: Vec<String> = agent::get_json(state, "/v1/tailscale/routes")
        .await
        .unwrap_or_default();
    let online = status
        .peers
        .values()
        .filter(|peer| peer.online == Some(true))
        .count();
    let offline = status
        .peers
        .values()
        .filter(|peer| peer.online == Some(false))
        .count();
    let peer_routes = count_by(status.peers.values().map(|peer| {
        peer.host_name
            .clone()
            .unwrap_or_else(|| "unnamed".to_owned())
    }));
    Ok(html! {
        (page_head("Tailscale", "Subnet router and peer state", html! {
            button class="btn" hx-get="/ui/tailscale" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        div class="summary-row" {
            (summary_item("Backend", status.backend_state.as_deref().unwrap_or("unknown"), "tailscale status"))
            (summary_item("Peers", &status.peers.len().to_string(), "tailnet nodes"))
            (summary_item("Online", &online.to_string(), "reachable peers"))
            (summary_item("Routes", &routes.len().to_string(), "advertised subnets"))
        }
        div class="tabs-strip" {
            a class="active" href="#tailnet-overview" { "Overview" }
            a href="#tailnet-routes" { "Routes" }
            a href="#tailnet-peers" { "Peers" }
        }
        section id="tailnet-overview" class="console-section section-spaced" {
            header { h2 { "Overview" } span class="muted" { "local node and peer health" } }
            div class="split-layout" {
                div {
                    h3 { "Local Node" }
                    dl class="facts" {
                        dt { "Backend" } dd { (status.backend_state.as_deref().unwrap_or("unknown")) }
                        @if let Some(node) = &status.self_node {
                            dt { "Host" } dd { (node.host_name.as_deref().unwrap_or("-")) }
                            dt { "Tailscale IPs" } dd { (join_or_dash(&node.tailscale_ips)) }
                            dt { "Online" } dd { (node.online.map(|v| v.to_string()).unwrap_or_else(|| "unknown".to_owned())) }
                        }
                    }
                }
                div {
                    h3 { "Peer Availability" }
                    (bar_chart(&BTreeMap::from([
                        ("online".to_owned(), online),
                        ("offline".to_owned(), offline),
                    ])))
                }
                div {
                    h3 { "Peer Inventory" }
                    (bar_chart(&peer_routes))
                }
            }
        }
        section id="tailnet-routes" class="console-section section-spaced" {
            header { h2 { "Advertised Routes" } span class="muted" { (routes.len()) " routes" } }
            @if routes.is_empty() {
                (empty("No advertised subnet routes reported by Tailscale."))
            } @else {
                div class="route-chips" {
                    @for route in &routes {
                        code { (route) }
                    }
                }
            }
        }
        section id="tailnet-peers" class="console-section" {
            header { h2 { "Peers" } span class="muted" { (status.peers.len()) " peers" } }
            div class="table-wrap" {
                table class="stable-table" {
                    thead { tr { th { "Host" } th { "State" } th { "Tailscale IPs" } th { "Allowed IPs / Routes" } } }
                    tbody {
                        @for peer in status.peers.values() {
                            tr {
                                td { (peer.host_name.as_deref().unwrap_or("-")) }
                                td { (status_pill(match peer.online { Some(true) => "active", Some(false) => "error", None => "pending" })) }
                                td class="mono" { (join_or_dash(&peer.tailscale_ips)) }
                                td class="mono wrap" { (join_or_dash(&peer.allowed_ips)) }
                            }
                        }
                    }
                }
            }
        }
    })
}

async fn events_markup(state: &AppState) -> Result<Markup, GatewayError> {
    let events: Vec<Event> = agent::get_json(state, "/v1/events").await?;
    let level_counts = count_by(events.iter().map(|event| wire_name(&event.level)));
    Ok(html! {
        (page_head("Logs", "Agent audit and reconcile log", html! {
            a class="btn" href="/ui/logs/download" { "Download" }
            button class="btn" type="button" disabled title="Requires edge-agent log rotation endpoint" { "Roll" }
            button class="btn" hx-get="/ui/logs" hx-target="#view" hx-swap="innerHTML transition:true" { "Refresh" }
        }))
        div class="summary-row compact-row" {
            (summary_item("Rows", &events.len().to_string(), "agent events"))
            (summary_item("Warn", &level_counts.get("warn").copied().unwrap_or_default().to_string(), "needs review"))
            (summary_item("Error", &level_counts.get("error").copied().unwrap_or_default().to_string(), "failed actions"))
            (summary_item("Source", "edge-agent", "event API"))
        }
        section class="console-section log-console" {
            header {
                h2 { "Raw Event Stream" }
                span class="muted" { "newest first" }
            }
            div class="log-toolbar" {
                button class="btn" type="button" data-log-filter="all" { "All" }
                button class="btn" type="button" data-log-filter="warn" { "Warn" }
                button class="btn" type="button" data-log-filter="error" { "Error" }
                button class="btn" type="button" data-copy-logs { "Copy" }
            }
            pre class="raw-log" data-raw-log {
                @if events.is_empty() {
                    "no events recorded\n"
                } @else {
                    (raw_log_markup(&events))
                }
            }
        }
    })
}

fn render_result(result: Result<Markup, GatewayError>) -> Html<String> {
    Html(match result {
        Ok(markup) => markup.into_string(),
        Err(error) => error_card(&error.message).into_string(),
    })
}

fn page_head(title: &str, eyebrow: &str, actions: Markup) -> Markup {
    html! {
        div class="page-head" {
            div { p class="eyebrow" { (eyebrow) } h1 { (title) } }
            div class="actions" { (actions) }
        }
    }
}

fn summary_item(label: &str, value: &str, meta: &str) -> Markup {
    html! {
        div class="summary-item" {
            span class="label" { (label) }
            strong class="mono" { (value) }
            span class="meta" { (meta) }
        }
    }
}

fn new_mapping_dialog() -> Markup {
    html! {
        dialog id="new-mapping-dialog" class="modal" {
            div class="modal-box" {
                header {
                    h2 { "New Mapping" }
                    button class="btn" type="button" data-close-dialog="new-mapping-dialog" { "Close" }
                }
                form class="mapping-form" hx-post="/ui/mappings" hx-target="#view" hx-swap="innerHTML transition:true" {
                    label class="field full" { span { "Name" } input name="name" required placeholder="mysql"; }
                    label class="field" { span { "Edge private IP" } input name="edge_private_ip" required placeholder="10.0.0.101"; }
                    label class="field" { span { "Target IP" } input name="target_ip" required placeholder="192.168.20.42"; }
                    label class="field" { span { "Public IP" } input name="public_ip" placeholder="optional"; }
                    label class="field" { span { "Public port" } input name="public_port" type="number" min="1" max="65535"; }
                    label class="field" { span { "Target port" } input name="target_port" type="number" min="1" max="65535"; }
                    label class="field" { span { "Protocol" } select name="protocol" { option value="all" { "all" } option value="tcp" { "tcp" } option value="udp" { "udp" } } }
                    label class="field" { span { "Mode" } select name="mode" { option value="one_to_one_snat" { "one_to_one_snat" } option value="port_forward_snat" { "port_forward_snat" } } }
                    label class="field" { span { "Backend" } select name="backend" { option value="nft" { "nft" } option value="xdp" { "xdp" } } }
                    div class="modal-actions" {
                        button class="btn" type="button" data-close-dialog="new-mapping-dialog" { "Cancel" }
                        button class="primary" type="submit" { "Create Mapping" }
                    }
                }
            }
        }
    }
}

fn inspect_dialog_id(mapping: &Mapping) -> String {
    format!("inspect-{}", mapping.id.as_str())
}

fn inspect_mapping_dialog(mapping: &Mapping, flow: Option<&TopologyFlow>) -> Markup {
    let dialog_id = inspect_dialog_id(mapping);
    let public = endpoint(
        mapping.public_ip.map(|ip| ip.to_string()),
        mapping.public_port,
    );
    let target = endpoint(Some(mapping.target_ip.to_string()), mapping.target_port);
    let checked_at = mapping
        .last_checked_at
        .map(format_time)
        .unwrap_or_else(|| "-".to_owned());

    html! {
        dialog id=(dialog_id.as_str()) class="modal modal-wide" {
            div class="modal-box" {
                header {
                    div {
                        h2 { "Inspect Mapping" }
                        p class="muted mono" { (mapping.id.as_str()) }
                    }
                    (status_pill(&mapping_status(mapping)))
                    button class="btn" type="button" data-close-dialog=(dialog_id.as_str()) { "Close" }
                }
                div class="inspect-body" {
                    div class="inspect-title" {
                        h3 { (&mapping.name) }
                        span class="muted" { (wire_name(&mapping.protocol)) " / " (wire_name(&mapping.mode)) " / " (wire_name(&mapping.backend)) }
                    }
                    div class="inspect-grid" {
                        dl class="facts compact" {
                            dt { "Enabled" } dd { (if mapping.enabled { "yes" } else { "no" }) }
                            dt { "Status" } dd { (wire_name(&mapping.status)) }
                            dt { "Health" } dd { (mapping.health_status.as_deref().unwrap_or("-")) }
                            dt { "Checked" } dd { (checked_at) }
                        }
                        dl class="facts compact" {
                            dt { "Public" } dd class="mono wrap" { (public) }
                            dt { "Edge" } dd class="mono wrap" { (mapping.edge_private_ip) }
                            dt { "Target" } dd class="mono wrap" { (target) }
                            dt { "Backend" } dd { (wire_name(&mapping.backend)) }
                        }
                        dl class="facts compact" {
                            dt { "Public OCID" } dd class="mono wrap" { (mapping.oci_public_ip_ocid.as_deref().unwrap_or("-")) }
                            dt { "Private OCID" } dd class="mono wrap" { (mapping.oci_private_ip_ocid.as_deref().unwrap_or("-")) }
                            dt { "Created" } dd { (format_time(mapping.created_at)) }
                            dt { "Updated" } dd { (format_time(mapping.updated_at)) }
                        }
                    }
                    @if let Some(error) = &mapping.last_error {
                        div class="inspect-alert" {
                            strong { "Last error" }
                            code { (error) }
                        }
                    }
                    @if let Some(flow) = flow {
                        div class="inspect-path" {
                            div class="path-node" {
                                span { "Public" }
                                code { (&flow.public_endpoint) }
                            }
                            span class="path-arrow" { "->" }
                            div class="path-node" {
                                span { "Edge" }
                                code { (&flow.edge_private_ip) }
                            }
                            span class="path-arrow" { "->" }
                            div class="path-node" {
                                span { "Target" }
                                code { (&flow.target_endpoint) }
                            }
                        }
                    } @else {
                        (empty("No topology bind found for this mapping."))
                    }
                }
            }
        }
    }
}

fn status_pill(status: &str) -> Markup {
    html! { span class=(format!("pill pill-{status}")) { (status) } }
}

fn tab_button_class(active_tab: &str, tab: &str) -> &'static str {
    if active_tab == tab {
        "sub-menu-item active"
    } else {
        "sub-menu-item"
    }
}

fn tab_panel_class(active_tab: &str, tab: &str) -> &'static str {
    if active_tab == tab {
        "tool-tab-panel active"
    } else {
        "tool-tab-panel"
    }
}

fn is_active_tab(active_tab: &str, tab: &str) -> &'static str {
    if active_tab == tab {
        "true"
    } else {
        "false"
    }
}

fn binding_diagrams(flows: &[TopologyFlow]) -> Markup {
    html! {
        @if flows.is_empty() {
            (empty("No mapping binds configured."))
        } @else {
            div class="bind-list" {
                @for flow in flows {
                    article class="bind-card" {
                        header {
                            strong { (&flow.name) }
                            span class="bind-meta" { (&flow.protocol) " / " (&flow.mode) " / " (&flow.backend) }
                            (status_pill(&flow.status))
                            @if !flow.enabled { (status_pill("disabled")) }
                        }
                        div class="bind-path" {
                            code { (&flow.public_endpoint) }
                            span { "->" }
                            code { (&flow.edge_private_ip) }
                            span { "->" }
                            code { (&flow.target_endpoint) }
                        }
                    }
                }
            }
        }
    }
}

fn bool_text(value: bool) -> &'static str {
    if value {
        "configured"
    } else {
        "missing"
    }
}

fn bar_chart(values: &BTreeMap<String, usize>) -> Markup {
    let max = values.values().copied().max().unwrap_or(0).max(1);
    html! {
        @if values.is_empty() || values.values().all(|value| *value == 0) {
            (empty("No live data for this chart."))
        } @else {
            div class="bars" {
                @for (label, value) in values {
                    div class="bar-row" {
                        span class="bar-label" { (label) }
                        div class="bar-track" {
                            div class=(format!("bar-fill bar-fill-{label}")) style=(format!("width: {}%", (*value * 100) / max)) {}
                        }
                        strong { (value) }
                    }
                }
            }
        }
    }
}

fn events_list(events: &[Event]) -> Markup {
    html! {
        @if events.is_empty() {
            (empty("No events recorded."))
        } @else {
            ol class="events" {
                @for event in events {
                    li {
                        time { (format_time(event.created_at)) }
                        span class=(format!("pill pill-{}", wire_name(&event.level))) { (wire_name(&event.level)) }
                        span class="msg" { (&event.message) }
                        @if let Some(data) = &event.data { code { (data) } }
                    }
                }
            }
        }
    }
}

fn raw_log_lines(events: &[Event]) -> String {
    events
        .iter()
        .map(|event| {
            let data = event
                .data
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!(" {value}"))
                .unwrap_or_default();
            format!(
                "{} {:<5} {}{}",
                format_time(event.created_at),
                wire_name(&event.level),
                event.message,
                data
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn raw_log_markup(events: &[Event]) -> Markup {
    html! {
        @for event in events {
            span class="log-line" data-level=(wire_name(&event.level)) {
                (format_time(event.created_at)) " " (format!("{:<5}", wire_name(&event.level))) " " (&event.message)
                @if let Some(data) = &event.data {
                    " " (data)
                }
                "\n"
            }
        }
    }
}

fn count_by(values: impl Iterator<Item = String>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

fn mapping_status(mapping: &Mapping) -> String {
    wire_name(&mapping.status)
}

fn format_time(value: time::OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn endpoint(ip: Option<String>, port: Option<u16>) -> String {
    match (ip, port) {
        (Some(ip), Some(port)) => format!("{ip}:{port}"),
        (Some(ip), None) => ip,
        _ => "-".to_owned(),
    }
}

fn clean_interface(value: &str) -> Result<&str, GatewayError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 32
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':'))
    {
        return Err(GatewayError::bad_gateway("invalid tcpdump interface"));
    }
    Ok(value)
}

fn clean_tcpdump_filter(value: Option<&str>) -> Result<Vec<String>, GatewayError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    if value.len() > 240 {
        return Err(GatewayError::bad_gateway("tcpdump filter is too long"));
    }
    let parts = value
        .split_whitespace()
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if parts.iter().any(|part| {
        part.starts_with('-') || part.contains(';') || part.contains('|') || part.contains('&')
    }) {
        return Err(GatewayError::bad_gateway(
            "tcpdump filter contains unsafe tokens",
        ));
    }
    Ok(parts)
}

fn tcpdump_report(stdout: &str, stderr: &str, requested_packets: u16, filter: &[String]) -> String {
    let packet_lines = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let tcp = stdout.matches(" TCP ").count() + stdout.matches(" Flags ").count();
    let udp = stdout.matches(" UDP").count();
    let icmp = stdout.matches(" ICMP").count();
    let arp = stdout.matches(" ARP").count();
    let mut report = format!(
        "Requested packets: {requested_packets}\nCaptured lines: {packet_lines}\nFilter: {}\n\nProtocol hints:\n  tcp: {tcp}\n  udp: {udp}\n  icmp: {icmp}\n  arp: {arp}\n",
        if filter.is_empty() {
            "(none)".to_owned()
        } else {
            filter.join(" ")
        }
    );
    if !stderr.trim().is_empty() {
        report.push_str("\nTcpdump status:\n");
        report.push_str(stderr.trim());
        report.push('\n');
    }
    if !stdout.trim().is_empty() {
        report.push_str("\nPackets:\n");
        report.push_str(stdout.trim());
        report.push('\n');
    }
    report
}

fn wire_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn clean_opt(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    })
}

fn clean_port(value: Option<String>) -> Result<Option<u16>, GatewayError> {
    clean_opt(value)
        .map(|value| value.parse::<u16>().map_err(GatewayError::bad_gateway))
        .transpose()
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(", ")
    }
}

fn empty(message: &str) -> Markup {
    html! { div class="empty" { p { (message) } } }
}

fn error_card(message: &str) -> Markup {
    html! { div class="card error-card" { div class="card-body" { h2 { "Request failed" } p { (message) } } } }
}
