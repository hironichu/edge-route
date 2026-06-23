use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::errors::{EdgeCoreError, Result};
use crate::mapping::{EdgeConfig, Mapping, MappingId, MappingMode, MappingStatus};
use crate::validation::{conflicts, validate_edge_config, validate_mapping};

pub const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS mappings (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_ip TEXT,
    oci_public_ip_ocid TEXT,
    edge_private_ip TEXT NOT NULL,
    oci_private_ip_ocid TEXT,
    target_ip TEXT NOT NULL,
    public_port INTEGER,
    target_port INTEGER,
    protocol TEXT NOT NULL DEFAULT 'all',
    mode TEXT NOT NULL DEFAULT 'one_to_one_snat',
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    health_status TEXT,
    last_checked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS edge_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS generations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,
    nftables_config TEXT NOT NULL,
    created_at TEXT NOT NULL,
    applied_at TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    created_at TEXT NOT NULL
);
"#;

pub trait StateStore {
    fn edge_config(&self) -> Option<&EdgeConfig>;
    fn set_edge_config(&mut self, config: EdgeConfig) -> Result<()>;

    fn insert_mapping(&mut self, mapping: Mapping) -> Result<()>;
    fn get_mapping(&self, id: &MappingId) -> Result<&Mapping>;
    fn list_mappings(&self) -> Vec<&Mapping>;
    fn update_mapping(&mut self, mapping: Mapping) -> Result<()>;
    fn delete_mapping(&mut self, id: &MappingId) -> Result<Mapping>;
    fn set_mapping_enabled(&mut self, id: &MappingId, enabled: bool) -> Result<()>;

    fn record_generation(&mut self, generation: NewGeneration) -> Result<Generation>;
    fn record_event(&mut self, event: NewEvent) -> Result<Event>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationStatus {
    Rendered,
    Validated,
    Active,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generation {
    pub id: i64,
    pub status: GenerationStatus,
    pub nftables_config: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub applied_at: Option<OffsetDateTime>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGeneration {
    pub status: GenerationStatus,
    pub nftables_config: String,
    pub applied_at: Option<OffsetDateTime>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub level: EventLevel,
    pub message: String,
    pub data: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    pub level: EventLevel,
    pub message: String,
    pub data: Option<String>,
}

#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    edge_config: Option<EdgeConfig>,
    mappings: BTreeMap<MappingId, Mapping>,
    generations: Vec<Generation>,
    events: Vec<Event>,
    next_generation_id: i64,
    next_event_id: i64,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self {
            next_generation_id: 1,
            next_event_id: 1,
            ..Self::default()
        }
    }

    pub fn generations(&self) -> &[Generation] {
        &self.generations
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    fn validate_mapping_for_write(&self, candidate: &Mapping) -> Result<()> {
        let config = self
            .edge_config
            .as_ref()
            .ok_or_else(|| EdgeCoreError::store("edge config must be set before mappings"))?;
        validate_mapping(candidate, config)?;

        for existing in self.mappings.values() {
            if existing.id == candidate.id {
                continue;
            }

            if let Some(public_ip) = candidate.public_ip {
                if existing.public_ip == Some(public_ip)
                    && (existing.mode == MappingMode::OneToOneSnat
                        || candidate.mode == MappingMode::OneToOneSnat)
                {
                    return Err(EdgeCoreError::DuplicatePublicIp(public_ip));
                }
            }

            if existing.mode == MappingMode::OneToOneSnat
                && candidate.mode == MappingMode::OneToOneSnat
                && existing.target_ip == candidate.target_ip
            {
                return Err(EdgeCoreError::DuplicateTargetIp(candidate.target_ip));
            } else if conflicts(existing, candidate) {
                return Err(EdgeCoreError::DuplicateEdgePrivateIp(
                    candidate.edge_private_ip,
                ));
            }
        }

        Ok(())
    }
}

impl StateStore for InMemoryStateStore {
    fn edge_config(&self) -> Option<&EdgeConfig> {
        self.edge_config.as_ref()
    }

    fn set_edge_config(&mut self, config: EdgeConfig) -> Result<()> {
        validate_edge_config(&config)?;

        for mapping in self.mappings.values() {
            validate_mapping(mapping, &config)?;
        }

        self.edge_config = Some(config);
        Ok(())
    }

    fn insert_mapping(&mut self, mapping: Mapping) -> Result<()> {
        if self.mappings.contains_key(&mapping.id) {
            return Err(EdgeCoreError::DuplicateMappingId(mapping.id));
        }

        self.validate_mapping_for_write(&mapping)?;
        self.mappings.insert(mapping.id.clone(), mapping);
        Ok(())
    }

    fn get_mapping(&self, id: &MappingId) -> Result<&Mapping> {
        self.mappings
            .get(id)
            .ok_or_else(|| EdgeCoreError::NotFound(id.clone()))
    }

    fn list_mappings(&self) -> Vec<&Mapping> {
        self.mappings.values().collect()
    }

    fn update_mapping(&mut self, mut mapping: Mapping) -> Result<()> {
        if !self.mappings.contains_key(&mapping.id) {
            return Err(EdgeCoreError::NotFound(mapping.id));
        }

        mapping.updated_at = OffsetDateTime::now_utc();
        self.validate_mapping_for_write(&mapping)?;
        self.mappings.insert(mapping.id.clone(), mapping);
        Ok(())
    }

    fn delete_mapping(&mut self, id: &MappingId) -> Result<Mapping> {
        self.mappings
            .remove(id)
            .ok_or_else(|| EdgeCoreError::NotFound(id.clone()))
    }

    fn set_mapping_enabled(&mut self, id: &MappingId, enabled: bool) -> Result<()> {
        let mapping = self
            .mappings
            .get_mut(id)
            .ok_or_else(|| EdgeCoreError::NotFound(id.clone()))?;
        mapping.enabled = enabled;
        mapping.status = if enabled {
            MappingStatus::Pending
        } else {
            MappingStatus::Disabled
        };
        mapping.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    fn record_generation(&mut self, generation: NewGeneration) -> Result<Generation> {
        if generation.nftables_config.trim().is_empty() {
            return Err(EdgeCoreError::validation(
                "generation nftables_config cannot be empty",
            ));
        }

        let generation = Generation {
            id: self.next_generation_id,
            status: generation.status,
            nftables_config: generation.nftables_config,
            created_at: OffsetDateTime::now_utc(),
            applied_at: generation.applied_at,
            error: generation.error,
        };
        self.next_generation_id += 1;
        self.generations.push(generation.clone());
        Ok(generation)
    }

    fn record_event(&mut self, event: NewEvent) -> Result<Event> {
        if event.message.trim().is_empty() {
            return Err(EdgeCoreError::validation("event message cannot be empty"));
        }

        let event = Event {
            id: self.next_event_id,
            level: event.level,
            message: event.message,
            data: event.data,
            created_at: OffsetDateTime::now_utc(),
        };
        self.next_event_id += 1;
        self.events.push(event.clone());
        Ok(event)
    }
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
    fn inserts_and_reads_mapping() {
        let mut store = InMemoryStateStore::new();
        store.set_edge_config(config()).unwrap();
        let mapping = mapping();
        let id = mapping.id.clone();

        store.insert_mapping(mapping.clone()).unwrap();

        assert_eq!(store.get_mapping(&id).unwrap(), &mapping);
        assert_eq!(store.list_mappings(), vec![&mapping]);
    }

    #[test]
    fn rejects_mapping_before_config() {
        let mut store = InMemoryStateStore::new();

        let err = store.insert_mapping(mapping()).unwrap_err();

        assert_eq!(
            err,
            EdgeCoreError::store("edge config must be set before mappings")
        );
    }

    #[test]
    fn rejects_duplicate_edge_private_ip() {
        let mut store = InMemoryStateStore::new();
        store.set_edge_config(config()).unwrap();
        let first = mapping();
        let mut second = mapping();
        second.id = MappingId::new();
        second.public_ip = Some("1.1.1.1".parse().unwrap());
        second.target_ip = "192.168.20.43".parse().unwrap();

        store.insert_mapping(first).unwrap();
        let err = store.insert_mapping(second).unwrap_err();

        assert_eq!(
            err,
            EdgeCoreError::DuplicateEdgePrivateIp("10.0.0.101".parse().unwrap())
        );
    }

    #[test]
    fn disabling_mapping_updates_status() {
        let mut store = InMemoryStateStore::new();
        store.set_edge_config(config()).unwrap();
        let mapping = mapping();
        let id = mapping.id.clone();
        store.insert_mapping(mapping).unwrap();

        store.set_mapping_enabled(&id, false).unwrap();

        let stored = store.get_mapping(&id).unwrap();
        assert!(!stored.enabled);
        assert_eq!(stored.status, MappingStatus::Disabled);
    }

    #[test]
    fn records_generation_and_event_ids() {
        let mut store = InMemoryStateStore::new();

        let generation = store
            .record_generation(NewGeneration {
                status: GenerationStatus::Rendered,
                nftables_config: "table ip edge_nat {}".to_owned(),
                applied_at: None,
                error: None,
            })
            .unwrap();
        let event = store
            .record_event(NewEvent {
                level: EventLevel::Info,
                message: "created mapping".to_owned(),
                data: None,
            })
            .unwrap();

        assert_eq!(generation.id, 1);
        assert_eq!(event.id, 1);
        assert_eq!(store.generations(), &[generation]);
        assert_eq!(store.events(), &[event]);
    }
}
