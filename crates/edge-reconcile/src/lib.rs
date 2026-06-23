use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use edge_core::{
    EdgeConfig, EdgeCoreError, EventLevel, GenerationStatus, MappingBackend, MappingStatus,
    Protocol,
};
use edge_linux::Linux;
use edge_nft::{render_nftables, Nft, NftRenderConfig};
use edge_store::SqliteStore;
use edge_xdp::{XdpConfig, XdpPlugin};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub type Result<T> = std::result::Result<T, ReconcileError>;

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error("{0}")]
    Core(#[from] EdgeCoreError),
    #[error("linux operation failed: {0}")]
    Linux(#[from] edge_linux::LinuxError),
    #[error("nft operation failed: {0}")]
    Nft(#[from] edge_nft::NftError),
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("nft validation failed: {0}")]
    NftValidation(String),
    #[error("nft apply failed: {0}")]
    NftApply(String),
    #[error("health check failed: {0}")]
    Health(String),
    #[error("xdp operation failed: {0}")]
    Xdp(#[from] edge_xdp::XdpError),
    #[error("xdp apply is not implemented; run dry-run to inspect the XDP plan")]
    XdpApplyUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOptions {
    pub nft_output: PathBuf,
    pub dry_run: bool,
    pub apply_nft: bool,
    pub apply_linux: bool,
    pub xdp: XdpConfig,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            nft_output: PathBuf::from("/run/edge-router/generated.nft"),
            dry_run: false,
            apply_nft: true,
            apply_linux: true,
            xdp: XdpConfig::disabled(""),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    pub nftables_config: String,
    pub generation_id: Option<i64>,
    pub added_addresses: Vec<String>,
    pub removed_addresses: Vec<String>,
    pub xdp_plan_entries: usize,
}

#[derive(Default)]
pub struct Reconciler {
    linux: Linux,
    nft: Nft,
}

impl Reconciler {
    pub fn new(linux: Linux, nft: Nft) -> Self {
        Self { linux, nft }
    }

    pub async fn reconcile(
        &self,
        store: &SqliteStore,
        config: &EdgeConfig,
        options: &ReconcileOptions,
    ) -> Result<ReconcileReport> {
        let mappings = store.list_mappings().await?;
        let rendered = render_nftables(&mappings, config, &NftRenderConfig::default())?;
        let xdp_plan = XdpPlugin::new(options.xdp.clone()).plan(&mappings, config)?;
        if options.dry_run {
            return Ok(ReconcileReport {
                nftables_config: rendered,
                generation_id: None,
                added_addresses: Vec::new(),
                removed_addresses: Vec::new(),
                xdp_plan_entries: xdp_plan.entries.len(),
            });
        }
        if !xdp_plan.is_empty() {
            return Err(ReconcileError::XdpApplyUnsupported);
        }

        let _rendered_generation = store
            .record_generation(GenerationStatus::Rendered, &rendered, None, None)
            .await?;
        if let Err(error) = atomic_write(&options.nft_output, rendered.as_bytes()) {
            let message = error.to_string();
            store
                .record_generation(GenerationStatus::Failed, &rendered, None, Some(&message))
                .await?;
            store
                .record_event(
                    EventLevel::Error,
                    "failed to write nftables config",
                    Some(&message),
                )
                .await?;
            return Err(error.into());
        }

        let check = self.nft.check_file(&options.nft_output).await?;
        if !check.is_success() {
            let message = check.error_message();
            store
                .record_generation(GenerationStatus::Failed, &rendered, None, Some(&message))
                .await?;
            store
                .record_event(EventLevel::Error, "nft validation failed", Some(&message))
                .await?;
            return Err(ReconcileError::NftValidation(message));
        }
        store
            .record_generation(GenerationStatus::Validated, &rendered, None, None)
            .await?;

        if options.apply_nft {
            let applied = self.nft.apply_file(&options.nft_output).await?;
            if !applied.is_success() {
                let message = applied.error_message();
                store
                    .record_generation(GenerationStatus::Failed, &rendered, None, Some(&message))
                    .await?;
                store
                    .record_event(EventLevel::Error, "nft apply failed", Some(&message))
                    .await?;
                return Err(ReconcileError::NftApply(message));
            }
        }

        let mut added_addresses = Vec::new();
        let mut removed_addresses = Vec::new();
        if options.apply_linux {
            for mapping in &mappings {
                if mapping.enabled && mapping.backend == MappingBackend::Nft {
                    if self
                        .linux
                        .ensure_addr(&config.wan_interface, mapping.edge_private_ip)
                        .await?
                    {
                        added_addresses.push(mapping.edge_private_ip.to_string());
                    }
                } else if mapping.backend == MappingBackend::Nft
                    && self
                        .linux
                        .delete_addr_if_present(&config.wan_interface, mapping.edge_private_ip)
                        .await?
                {
                    removed_addresses.push(mapping.edge_private_ip.to_string());
                }
            }
        }

        let generation_id = if options.apply_nft && options.apply_linux {
            let active = store
                .record_generation(
                    GenerationStatus::Active,
                    &rendered,
                    Some(OffsetDateTime::now_utc()),
                    None,
                )
                .await?;
            for mapping in mappings
                .iter()
                .filter(|mapping| mapping.enabled && mapping.backend == MappingBackend::Nft)
            {
                match health_check(mapping.target_ip, mapping.target_port, mapping.protocol).await {
                    Ok(status) => {
                        store
                            .set_mapping_health(
                                &mapping.id,
                                MappingStatus::Active,
                                Some(status),
                                None,
                            )
                            .await?;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        store
                            .set_mapping_health(
                                &mapping.id,
                                MappingStatus::Degraded,
                                Some("degraded"),
                                Some(&message),
                            )
                            .await?;
                        store
                            .record_event(
                                EventLevel::Warn,
                                "mapping health degraded",
                                Some(&message),
                            )
                            .await?;
                    }
                }
            }
            store
                .record_event(
                    EventLevel::Info,
                    "reconcile applied",
                    Some(&format!("generation={}", active.id)),
                )
                .await?;
            active.id
        } else {
            store
                .record_event(
                    EventLevel::Info,
                    "reconcile validated without full apply",
                    Some(&format!(
                        "apply_nft={},apply_linux={}",
                        options.apply_nft, options.apply_linux
                    )),
                )
                .await?;
            _rendered_generation.id
        };

        Ok(ReconcileReport {
            nftables_config: rendered,
            generation_id: Some(generation_id),
            added_addresses,
            removed_addresses,
            xdp_plan_entries: xdp_plan.entries.len(),
        })
    }

    pub async fn rollback(
        &self,
        store: &SqliteStore,
        generation_id: i64,
        nft_output: &Path,
    ) -> Result<()> {
        let generation = store.get_generation(generation_id).await?;
        atomic_write(nft_output, generation.nftables_config.as_bytes())?;
        let check = self.nft.check_file(nft_output).await?;
        if !check.is_success() {
            let message = check.error_message();
            store
                .record_event(
                    EventLevel::Error,
                    "rollback nft validation failed",
                    Some(&message),
                )
                .await?;
            return Err(ReconcileError::NftValidation(message));
        }
        let applied = self.nft.apply_file(nft_output).await?;
        if !applied.is_success() {
            let message = applied.error_message();
            store
                .record_event(
                    EventLevel::Error,
                    "rollback nft apply failed",
                    Some(&message),
                )
                .await?;
            return Err(ReconcileError::NftApply(message));
        }
        store
            .record_event(
                EventLevel::Warn,
                "rollback applied",
                Some(&format!("generation={generation_id}")),
            )
            .await?;
        Ok(())
    }
}

async fn health_check(
    target_ip: std::net::Ipv4Addr,
    target_port: Option<u16>,
    protocol: Protocol,
) -> Result<&'static str> {
    if protocol == Protocol::Udp {
        return Ok("udp_unchecked");
    }
    let Some(port) = target_port else {
        return Ok("ok");
    };
    let addr = SocketAddr::from((target_ip, port));
    timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .map_err(|_| ReconcileError::Health(format!("timed out: {addr}")))?
        .map_err(|error| ReconcileError::Health(format!("{addr}: {error}")))?;
    Ok("tcp_ok")
}

fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let tmp = path.with_extension(format!("tmp-{unique}"));
    {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_core::{Mapping, MappingBackend, MappingMode};

    #[test]
    fn atomic_write_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("generated.nft");

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "second");
    }

    #[tokio::test]
    async fn dry_run_reports_xdp_plan_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::connect(dir.path().join("state.sqlite"))
            .await
            .unwrap();
        let config = EdgeConfig::new("ens3", "tailscale0", vec!["10.10.40.0/24".parse().unwrap()]);
        store.set_edge_config(&config).await.unwrap();
        store.insert_mapping(&xdp_mapping()).await.unwrap();
        let options = ReconcileOptions {
            dry_run: true,
            xdp: XdpConfig::enabled("ens3", "/sys/fs/bpf/edgeroute"),
            ..ReconcileOptions::default()
        };

        let report = Reconciler::default()
            .reconcile(&store, &config, &options)
            .await
            .unwrap();

        assert_eq!(report.xdp_plan_entries, 1);
        assert!(report.nftables_config.contains("table ip edge_nat"));
    }

    #[tokio::test]
    async fn apply_rejects_xdp_until_loader_exists() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::connect(dir.path().join("state.sqlite"))
            .await
            .unwrap();
        let config = EdgeConfig::new("ens3", "tailscale0", vec!["10.10.40.0/24".parse().unwrap()]);
        store.set_edge_config(&config).await.unwrap();
        store.insert_mapping(&xdp_mapping()).await.unwrap();
        let options = ReconcileOptions {
            nft_output: dir.path().join("generated.nft"),
            xdp: XdpConfig::enabled("ens3", "/sys/fs/bpf/edgeroute"),
            ..ReconcileOptions::default()
        };

        let err = Reconciler::default()
            .reconcile(&store, &config, &options)
            .await
            .unwrap_err();

        assert!(matches!(err, ReconcileError::XdpApplyUnsupported));
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
}
