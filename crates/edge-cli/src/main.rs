use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use edge_core::{EdgeConfig, Mapping, MappingId, MappingStatus};
use edge_nft::{render_nftables, NftRenderConfig};
use edge_oci::OciCli;
use edge_reconcile::{ReconcileOptions, Reconciler};
use edge_store::SqliteStore;
use edge_tailscale::TailscaleCli;
use ipnet::Ipv4Net;
use serde::Deserialize;

#[derive(Debug, Parser)]
#[command(name = "edge", about = "Edge router controller")]
struct Cli {
    #[arg(
        long,
        env = "EDGE_DB",
        default_value = "/var/lib/edge-router/state.sqlite"
    )]
    db: PathBuf,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(long, default_value = "ens3")]
    wan_interface: String,

    #[arg(long, default_value = "tailscale0")]
    tailscale_interface: String,

    #[arg(long = "home-cidr", default_value = "192.168.0.0/16")]
    home_cidrs: Vec<Ipv4Net>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Map {
        #[command(subcommand)]
        command: MapCommand,
    },
    Apply(ApplyArgs),
    Reconcile(ReconcileArgs),
    Rollback(RollbackArgs),
    Oracle {
        #[command(subcommand)]
        command: OracleCommand,
    },
    Status,
    Tailscale {
        #[command(subcommand)]
        command: TailscaleCommand,
    },
}

#[derive(Debug, Subcommand)]
enum MapCommand {
    Create(CreateMappingArgs),
    List,
    Get { id: String },
    Delete(DeleteMappingArgs),
    Enable { id: String },
    Disable { id: String },
}

#[derive(Debug, Args)]
struct CreateMappingArgs {
    #[arg(long)]
    edge_private_ip: Ipv4Addr,

    #[arg(long)]
    target: Ipv4Addr,

    #[arg(long)]
    public_ip: Option<Ipv4Addr>,

    #[arg(long)]
    target_port: Option<u16>,

    #[arg(long)]
    name: Option<String>,

    #[arg(long)]
    skip_route_check: bool,
}

#[derive(Debug, Args)]
struct DeleteMappingArgs {
    id: String,

    #[arg(long)]
    keep_oci_resources: bool,

    #[arg(long)]
    skip_reconcile: bool,

    #[arg(long, default_value = "/run/edge-router/generated.nft")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    check: bool,

    #[arg(long, default_value = "/run/edge-router/generated.nft")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ReconcileArgs {
    #[arg(long)]
    dry_run: bool,

    #[arg(long)]
    skip_linux: bool,

    #[arg(long)]
    skip_nft: bool,

    #[arg(long, default_value = "/run/edge-router/generated.nft")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct RollbackArgs {
    generation_id: i64,

    #[arg(long, default_value = "/run/edge-router/generated.nft")]
    output: PathBuf,
}

#[derive(Debug, Subcommand)]
enum OracleCommand {
    Ip {
        #[command(subcommand)]
        command: OracleIpCommand,
    },
    Vnic {
        #[command(subcommand)]
        command: OracleVnicCommand,
    },
}

#[derive(Debug, Subcommand)]
enum OracleIpCommand {
    List {
        #[arg(long)]
        compartment_id: String,
    },
    Allocate {
        mapping_id: String,
        #[arg(long)]
        compartment_id: String,
        #[arg(long)]
        vnic_id: String,
        #[arg(long)]
        display_name: Option<String>,
    },
    Release {
        #[arg(long)]
        public_ip_id: String,
        #[arg(long)]
        private_ip_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum OracleVnicCommand {
    Check {
        #[arg(long)]
        vnic_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum TailscaleCommand {
    Status,
    Routes,
    Check {
        target: Ipv4Addr,
        #[arg(long)]
        ping: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(
        cli.config.as_deref(),
        cli.wan_interface,
        cli.tailscale_interface,
        cli.home_cidrs,
    )?;
    let store = SqliteStore::connect(&cli.db)
        .await
        .with_context(|| format!("open state database {}", cli.db.display()))?;
    let config = store.ensure_edge_config(config).await?;

    match cli.command {
        Command::Map { command } => handle_map(command, &store, &config).await,
        Command::Apply(args) => handle_apply(args, &store, &config).await,
        Command::Reconcile(args) => handle_reconcile(args, &store, &config).await,
        Command::Rollback(args) => handle_rollback(args, &store).await,
        Command::Oracle { command } => handle_oracle(command, &store).await,
        Command::Status => handle_status(&store, &config).await,
        Command::Tailscale { command } => handle_tailscale(command).await,
    }
}

async fn handle_map(command: MapCommand, store: &SqliteStore, config: &EdgeConfig) -> Result<()> {
    match command {
        MapCommand::Create(args) => {
            if !args.skip_route_check {
                validate_tailscale_route(args.target, &config.tailscale_interface).await?;
            }
            let name = args
                .name
                .unwrap_or_else(|| format!("target_{}", args.target).replace('.', "_"));
            let mut mapping = Mapping::new(name, args.public_ip, args.edge_private_ip, args.target);
            mapping.target_port = args.target_port;
            store.insert_mapping(&mapping).await?;
            println!("Created mapping: {}", mapping.id);
            if let Some(public_ip) = mapping.public_ip {
                println!("Public IP: {public_ip}");
            }
            println!("Edge private IP: {}", mapping.edge_private_ip);
            println!("Target IP: {}", mapping.target_ip);
            println!("Status: {:?}", mapping.status);
        }
        MapCommand::List => {
            for mapping in store.list_mappings().await? {
                print_mapping_line(&mapping);
            }
        }
        MapCommand::Get { id } => {
            let id = MappingId::from_str(&id)?;
            let mapping = store.get_mapping(&id).await?;
            print_mapping_line(&mapping);
        }
        MapCommand::Delete(args) => {
            let id = MappingId::from_str(&args.id)?;
            let mapping = store.get_mapping(&id).await?;
            store.set_mapping_enabled(&id, false).await?;
            if !args.skip_reconcile {
                let options = ReconcileOptions {
                    nft_output: args.output,
                    dry_run: false,
                    apply_nft: true,
                    apply_linux: true,
                };
                Reconciler::default()
                    .reconcile(store, config, &options)
                    .await
                    .with_context(|| format!("reconcile disabled mapping {}", id))?;
            }
            if !args.keep_oci_resources {
                cleanup_mapping_oci(&mapping).await?;
            }
            let mapping = store.delete_mapping(&id).await?;
            println!("Deleted mapping: {}", mapping.id);
        }
        MapCommand::Enable { id } => {
            let id = MappingId::from_str(&id)?;
            let mapping = store.set_mapping_enabled(&id, true).await?;
            println!("Enabled mapping: {}", mapping.id);
        }
        MapCommand::Disable { id } => {
            let id = MappingId::from_str(&id)?;
            let mapping = store.set_mapping_enabled(&id, false).await?;
            println!("Disabled mapping: {}", mapping.id);
        }
    }
    Ok(())
}

async fn handle_apply(args: ApplyArgs, store: &SqliteStore, config: &EdgeConfig) -> Result<()> {
    let mappings = store.list_mappings().await?;
    let rendered = render_nftables(&mappings, config, &NftRenderConfig::default())?;

    if args.dry_run && args.check {
        anyhow::bail!("--dry-run and --check are mutually exclusive");
    }

    if args.dry_run {
        print!("{rendered}");
        return Ok(());
    }

    let output = args.output.clone();
    let options = ReconcileOptions {
        nft_output: args.output,
        dry_run: false,
        apply_nft: !args.check,
        apply_linux: !args.check,
    };
    Reconciler::default()
        .reconcile(store, config, &options)
        .await?;
    if args.check {
        println!("nft validation ok: {}", output.display());
    } else {
        println!("Applied nftables config: {}", output.display());
    }
    Ok(())
}

async fn handle_reconcile(
    args: ReconcileArgs,
    store: &SqliteStore,
    config: &EdgeConfig,
) -> Result<()> {
    let options = ReconcileOptions {
        nft_output: args.output,
        dry_run: args.dry_run,
        apply_nft: !args.skip_nft,
        apply_linux: !args.skip_linux,
    };
    let report = Reconciler::default()
        .reconcile(store, config, &options)
        .await?;
    if args.dry_run {
        print!("{}", report.nftables_config);
    } else {
        println!("Reconciled generation: {:?}", report.generation_id);
        println!("Added addresses: {}", report.added_addresses.join(","));
        println!("Removed addresses: {}", report.removed_addresses.join(","));
    }
    Ok(())
}

async fn handle_rollback(args: RollbackArgs, store: &SqliteStore) -> Result<()> {
    Reconciler::default()
        .rollback(store, args.generation_id, &args.output)
        .await?;
    println!("Rolled back to generation: {}", args.generation_id);
    Ok(())
}

async fn handle_oracle(command: OracleCommand, store: &SqliteStore) -> Result<()> {
    let oci = OciCli::default();
    match command {
        OracleCommand::Ip { command } => match command {
            OracleIpCommand::List { compartment_id } => {
                for public_ip in oci.list_public_ips(&compartment_id).await? {
                    println!(
                        "{}\t{}\t{}\t{}",
                        public_ip.id,
                        public_ip.ip_address,
                        public_ip.private_ip_id.as_deref().unwrap_or("-"),
                        public_ip.lifecycle_state.as_deref().unwrap_or("-")
                    );
                }
            }
            OracleIpCommand::Allocate {
                mapping_id,
                compartment_id,
                vnic_id,
                display_name,
            } => {
                let id = MappingId::from_str(&mapping_id)?;
                let mut mapping = store.get_mapping(&id).await?;
                if mapping.public_ip.is_some()
                    || mapping.oci_public_ip_ocid.is_some()
                    || mapping.oci_private_ip_ocid.is_some()
                {
                    anyhow::bail!("mapping already has OCI allocation fields: {id}");
                }

                let name = display_name.unwrap_or_else(|| mapping.name.clone());
                oci.validate_forwarding_vnic(&vnic_id).await?;
                let private_ip = oci.create_private_ip(&vnic_id, Some(&name)).await?;
                let public_ip = match oci
                    .create_reserved_public_ip(&compartment_id, &private_ip.id, Some(&name))
                    .await
                {
                    Ok(public_ip) => public_ip,
                    Err(error) => {
                        let cleanup = oci.delete_private_ip(&private_ip.id).await;
                        if let Err(cleanup_error) = cleanup {
                            anyhow::bail!(
                                "public IP allocation failed: {error}; private IP cleanup failed: {cleanup_error}"
                            );
                        }
                        return Err(error.into());
                    }
                };

                mapping.edge_private_ip = private_ip.ip_address;
                mapping.public_ip = Some(public_ip.ip_address);
                mapping.oci_private_ip_ocid = Some(private_ip.id);
                mapping.oci_public_ip_ocid = Some(public_ip.id);
                mapping.mark_status(MappingStatus::Pending);
                if let Err(error) = store.update_mapping(&mapping).await {
                    let public_cleanup = oci
                        .delete_public_ip(mapping.oci_public_ip_ocid.as_ref().unwrap())
                        .await;
                    let private_cleanup = oci
                        .delete_private_ip(mapping.oci_private_ip_ocid.as_ref().unwrap())
                        .await;
                    match (public_cleanup, private_cleanup) {
                        (Ok(()), Ok(())) => {
                            anyhow::bail!("database update failed after OCI allocation; cleaned up OCI resources: {error}");
                        }
                        (public_result, private_result) => {
                            anyhow::bail!(
                                "database update failed after OCI allocation: {error}; public IP cleanup: {:?}; private IP cleanup: {:?}",
                                public_result.err(),
                                private_result.err()
                            );
                        }
                    }
                }

                println!("Allocated public IP: {}", mapping.public_ip.unwrap());
                println!("Allocated OCI private IP: {}", mapping.edge_private_ip);
                println!(
                    "OCI public IP OCID: {}",
                    mapping.oci_public_ip_ocid.as_deref().unwrap_or("-")
                );
                println!(
                    "OCI private IP OCID: {}",
                    mapping.oci_private_ip_ocid.as_deref().unwrap_or("-")
                );
            }
            OracleIpCommand::Release {
                public_ip_id,
                private_ip_id,
            } => {
                oci.delete_public_ip(&public_ip_id).await?;
                println!("Released public IP: {public_ip_id}");
                if let Some(private_ip_id) = private_ip_id {
                    oci.delete_private_ip(&private_ip_id).await?;
                    println!("Deleted private IP: {private_ip_id}");
                }
            }
        },
        OracleCommand::Vnic { command } => match command {
            OracleVnicCommand::Check { vnic_id } => {
                let config = store.edge_config().await?;
                let vnic_id = vnic_id
                    .or_else(|| config.and_then(|config| config.oci_vnic_id))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing VNIC ID; pass --vnic-id or set oci_vnic_id in config"
                        )
                    })?;
                let vnic = oci.validate_forwarding_vnic(&vnic_id).await?;
                println!(
                    "VNIC forwarding check ok: {} ({})",
                    vnic.id,
                    vnic.display_name.as_deref().unwrap_or("-")
                );
            }
        },
    }
    Ok(())
}

async fn cleanup_mapping_oci(mapping: &Mapping) -> Result<()> {
    let oci = OciCli::default();
    let mut failures = Vec::new();
    if let Some(public_ip_id) = mapping.oci_public_ip_ocid.as_deref() {
        match oci.delete_public_ip(public_ip_id).await {
            Ok(()) => println!("Deleted OCI public IP: {public_ip_id}"),
            Err(error) if is_oci_not_found(&error) => {
                println!("OCI public IP already absent: {public_ip_id}");
            }
            Err(error) => failures.push(format!("public IP {public_ip_id}: {error}")),
        }
    }
    if let Some(private_ip_id) = mapping.oci_private_ip_ocid.as_deref() {
        match oci.delete_private_ip(private_ip_id).await {
            Ok(()) => println!("Deleted OCI private IP: {private_ip_id}"),
            Err(error) if is_oci_not_found(&error) => {
                println!("OCI private IP already absent: {private_ip_id}");
            }
            Err(error) => failures.push(format!("private IP {private_ip_id}: {error}")),
        }
    }
    if !failures.is_empty() {
        anyhow::bail!("OCI cleanup failed: {}", failures.join("; "));
    }
    Ok(())
}

fn is_oci_not_found(error: &edge_oci::OciError) -> bool {
    let text = error.to_string().to_ascii_lowercase();
    text.contains("notfound") || text.contains("not found") || text.contains("404")
}

async fn validate_tailscale_route(target: Ipv4Addr, tailscale_interface: &str) -> Result<()> {
    let tailscale = TailscaleCli::default();
    let route = tailscale.route_get(target).await?;
    if !route.route.contains(tailscale_interface) {
        anyhow::bail!(
            "target route does not use {}: {}",
            tailscale_interface,
            route.route
        );
    }
    Ok(())
}

async fn handle_tailscale(command: TailscaleCommand) -> Result<()> {
    let tailscale = TailscaleCli::default();
    match command {
        TailscaleCommand::Status => {
            let status = tailscale.status().await?;
            println!(
                "BackendState: {}",
                status.backend_state.as_deref().unwrap_or("unknown")
            );
            if let Some(self_node) = status.self_node {
                println!("Self: {}", self_node.host_name.as_deref().unwrap_or("-"));
                println!("TailscaleIPs: {}", self_node.tailscale_ips.join(","));
            }
            println!("Peers: {}", status.peers.len());
        }
        TailscaleCommand::Routes => {
            let status = tailscale.status().await?;
            for route in status.advertised_routes() {
                println!("{route}");
            }
        }
        TailscaleCommand::Check { target, ping } => {
            let route = tailscale.route_get(target).await?;
            println!("Route: {}", route.route);
            println!("Via tailscale0: {}", route.via_tailscale);
            if !route.via_tailscale {
                anyhow::bail!("target route does not use tailscale0: {target}");
            }
            if ping {
                tailscale.ping_once(target).await?;
                println!("Ping: ok");
            }
        }
    }
    Ok(())
}

async fn handle_status(store: &SqliteStore, config: &EdgeConfig) -> Result<()> {
    let mappings = store.list_mappings().await?;
    let enabled = mappings.iter().filter(|mapping| mapping.enabled).count();
    println!("WAN interface: {}", config.wan_interface);
    println!("Tailscale interface: {}", config.tailscale_interface);
    println!("Home CIDRs: {:?}", config.home_cidrs);
    println!("Mappings: {} total, {} enabled", mappings.len(), enabled);
    Ok(())
}

fn print_mapping_line(mapping: &Mapping) {
    let public_ip = mapping
        .public_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "-".to_owned());
    println!(
        "{}\t{}\t{}\t{}\t{:?}\tenabled={}",
        mapping.id,
        public_ip,
        mapping.edge_private_ip,
        mapping.target_ip,
        mapping.status,
        mapping.enabled
    );
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    wan_interface: Option<String>,
    tailscale_interface: Option<String>,
    home_cidrs: Option<Vec<Ipv4Net>>,
    oci_compartment_id: Option<String>,
    oci_vnic_id: Option<String>,
    oci_subnet_id: Option<String>,
    oci_nsg_ids: Option<Vec<String>>,
    api_token: Option<String>,
}

fn load_config(
    path: Option<&std::path::Path>,
    wan_interface: String,
    tailscale_interface: String,
    home_cidrs: Vec<Ipv4Net>,
) -> Result<EdgeConfig> {
    let mut config = EdgeConfig::new(wan_interface, tailscale_interface, home_cidrs);
    let Some(path) = path else {
        return Ok(config);
    };
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let file: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
    if let Some(value) = file.wan_interface {
        config.wan_interface = value;
    }
    if let Some(value) = file.tailscale_interface {
        config.tailscale_interface = value;
    }
    if let Some(value) = file.home_cidrs {
        config.home_cidrs = value;
    }
    config.oci_compartment_id = file.oci_compartment_id;
    config.oci_vnic_id = file.oci_vnic_id;
    config.oci_subnet_id = file.oci_subnet_id;
    config.oci_nsg_ids = file.oci_nsg_ids.unwrap_or_default();
    config.api_token = file.api_token;
    Ok(config)
}
