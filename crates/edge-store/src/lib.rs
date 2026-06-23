use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use edge_core::state::SQLITE_SCHEMA;
use edge_core::validation::{validate_edge_config, validate_mapping};
use edge_core::{
    EdgeConfig, EdgeCoreError, Event, EventLevel, Generation, GenerationStatus, Mapping, MappingId,
    MappingStatus,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(path: impl AsRef<Path>) -> edge_core::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                EdgeCoreError::store(format!("failed to create database directory: {error}"))
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(sql_error)?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn migrate(&self) -> edge_core::Result<()> {
        sqlx::query(SQLITE_SCHEMA)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        self.ensure_column("mappings", "health_status", "TEXT")
            .await?;
        self.ensure_column("mappings", "last_checked_at", "TEXT")
            .await?;
        Ok(())
    }

    async fn ensure_column(
        &self,
        table: &str,
        column: &str,
        definition: &str,
    ) -> edge_core::Result<()> {
        let pragma = format!("PRAGMA table_info({table})");
        let exists = sqlx::query(&pragma)
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .iter()
            .any(|row| row.get::<String, _>("name") == column);
        if !exists {
            let alter = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
            sqlx::query(&alter)
                .execute(&self.pool)
                .await
                .map_err(sql_error)?;
        }
        Ok(())
    }

    pub async fn set_edge_config(&self, config: &EdgeConfig) -> edge_core::Result<()> {
        validate_edge_config(config)?;
        let value = serde_json::to_string(config)
            .map_err(|error| EdgeCoreError::store(format!("encode edge config: {error}")))?;
        sqlx::query(
            "INSERT INTO edge_config (key, value) VALUES ('default', ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    pub async fn edge_config(&self) -> edge_core::Result<Option<EdgeConfig>> {
        let row = sqlx::query("SELECT value FROM edge_config WHERE key = 'default'")
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(|row| {
            let value: String = row.get("value");
            serde_json::from_str(&value)
                .map_err(|error| EdgeCoreError::store(format!("decode edge config: {error}")))
        })
        .transpose()
    }

    pub async fn ensure_edge_config(&self, config: EdgeConfig) -> edge_core::Result<EdgeConfig> {
        if let Some(existing) = self.edge_config().await? {
            return Ok(existing);
        }
        self.set_edge_config(&config).await?;
        Ok(config)
    }

    pub async fn insert_mapping(&self, mapping: &Mapping) -> edge_core::Result<()> {
        let config = self
            .edge_config()
            .await?
            .ok_or_else(|| EdgeCoreError::store("edge config must be set before mappings"))?;
        validate_mapping(mapping, &config)?;
        self.reject_duplicates(mapping).await?;

        sqlx::query(
            "INSERT INTO mappings (
                id, name, public_ip, oci_public_ip_ocid, edge_private_ip,
                oci_private_ip_ocid, target_ip, target_port, protocol, mode,
                enabled, status, last_error, health_status, last_checked_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(mapping.id.as_str())
        .bind(&mapping.name)
        .bind(mapping.public_ip.map(|ip| ip.to_string()))
        .bind(&mapping.oci_public_ip_ocid)
        .bind(mapping.edge_private_ip.to_string())
        .bind(&mapping.oci_private_ip_ocid)
        .bind(mapping.target_ip.to_string())
        .bind(mapping.target_port.map(i64::from))
        .bind(enum_string(&mapping.protocol)?)
        .bind(enum_string(&mapping.mode)?)
        .bind(mapping.enabled)
        .bind(enum_string(&mapping.status)?)
        .bind(&mapping.last_error)
        .bind(&mapping.health_status)
        .bind(format_optional_time(mapping.last_checked_at)?)
        .bind(format_time(mapping.created_at)?)
        .bind(format_time(mapping.updated_at)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    pub async fn get_mapping(&self, id: &MappingId) -> edge_core::Result<Mapping> {
        let row = sqlx::query("SELECT * FROM mappings WHERE id = ?")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?
            .ok_or_else(|| EdgeCoreError::NotFound(id.clone()))?;
        row_to_mapping(row)
    }

    pub async fn list_mappings(&self) -> edge_core::Result<Vec<Mapping>> {
        sqlx::query("SELECT * FROM mappings ORDER BY created_at, id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .into_iter()
            .map(row_to_mapping)
            .collect()
    }

    pub async fn delete_mapping(&self, id: &MappingId) -> edge_core::Result<Mapping> {
        let mapping = self.get_mapping(id).await?;
        sqlx::query("DELETE FROM mappings WHERE id = ?")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        Ok(mapping)
    }

    pub async fn update_mapping(&self, mapping: &Mapping) -> edge_core::Result<()> {
        let config = self
            .edge_config()
            .await?
            .ok_or_else(|| EdgeCoreError::store("edge config must be set before mappings"))?;
        validate_mapping(mapping, &config)?;
        self.reject_duplicates(mapping).await?;

        let result = sqlx::query(
            "UPDATE mappings SET
                name = ?, public_ip = ?, oci_public_ip_ocid = ?, edge_private_ip = ?,
                oci_private_ip_ocid = ?, target_ip = ?, target_port = ?, protocol = ?,
                mode = ?, enabled = ?, status = ?, last_error = ?, health_status = ?,
                last_checked_at = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(&mapping.name)
        .bind(mapping.public_ip.map(|ip| ip.to_string()))
        .bind(&mapping.oci_public_ip_ocid)
        .bind(mapping.edge_private_ip.to_string())
        .bind(&mapping.oci_private_ip_ocid)
        .bind(mapping.target_ip.to_string())
        .bind(mapping.target_port.map(i64::from))
        .bind(enum_string(&mapping.protocol)?)
        .bind(enum_string(&mapping.mode)?)
        .bind(mapping.enabled)
        .bind(enum_string(&mapping.status)?)
        .bind(&mapping.last_error)
        .bind(&mapping.health_status)
        .bind(format_optional_time(mapping.last_checked_at)?)
        .bind(format_time(mapping.updated_at)?)
        .bind(mapping.id.as_str())
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(EdgeCoreError::NotFound(mapping.id.clone()));
        }
        Ok(())
    }

    pub async fn set_mapping_enabled(
        &self,
        id: &MappingId,
        enabled: bool,
    ) -> edge_core::Result<Mapping> {
        let status = if enabled {
            MappingStatus::Pending
        } else {
            MappingStatus::Disabled
        };
        sqlx::query("UPDATE mappings SET enabled = ?, status = ?, updated_at = ? WHERE id = ?")
            .bind(enabled)
            .bind(enum_string(&status)?)
            .bind(format_time(OffsetDateTime::now_utc())?)
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        self.get_mapping(id).await
    }

    pub async fn set_mapping_health(
        &self,
        id: &MappingId,
        status: MappingStatus,
        health_status: Option<&str>,
        last_error: Option<&str>,
    ) -> edge_core::Result<Mapping> {
        sqlx::query(
            "UPDATE mappings SET status = ?, health_status = ?, last_error = ?,
                last_checked_at = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(enum_string(&status)?)
        .bind(health_status)
        .bind(last_error)
        .bind(format_time(OffsetDateTime::now_utc())?)
        .bind(format_time(OffsetDateTime::now_utc())?)
        .bind(id.as_str())
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        self.get_mapping(id).await
    }

    pub async fn record_generation(
        &self,
        status: GenerationStatus,
        nftables_config: &str,
        applied_at: Option<OffsetDateTime>,
        error: Option<&str>,
    ) -> edge_core::Result<Generation> {
        if nftables_config.trim().is_empty() {
            return Err(EdgeCoreError::validation(
                "generation nftables_config cannot be empty",
            ));
        }
        let created_at = OffsetDateTime::now_utc();
        let result = sqlx::query(
            "INSERT INTO generations (status, nftables_config, created_at, applied_at, error)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(enum_string(&status)?)
        .bind(nftables_config)
        .bind(format_time(created_at)?)
        .bind(format_optional_time(applied_at)?)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(Generation {
            id: result.last_insert_rowid(),
            status,
            nftables_config: nftables_config.to_owned(),
            created_at,
            applied_at,
            error: error.map(str::to_owned),
        })
    }

    pub async fn latest_active_generation(&self) -> edge_core::Result<Option<Generation>> {
        let row = sqlx::query(
            "SELECT * FROM generations WHERE status = 'active' ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?;
        row.map(row_to_generation).transpose()
    }

    pub async fn get_generation(&self, id: i64) -> edge_core::Result<Generation> {
        let row = sqlx::query("SELECT * FROM generations WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?
            .ok_or_else(|| EdgeCoreError::store(format!("generation not found: {id}")))?;
        row_to_generation(row)
    }

    pub async fn record_event(
        &self,
        level: EventLevel,
        message: &str,
        data: Option<&str>,
    ) -> edge_core::Result<Event> {
        if message.trim().is_empty() {
            return Err(EdgeCoreError::validation("event message cannot be empty"));
        }
        let created_at = OffsetDateTime::now_utc();
        let result = sqlx::query(
            "INSERT INTO events (level, message, data, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(enum_string(&level)?)
        .bind(message)
        .bind(data)
        .bind(format_time(created_at)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(Event {
            id: result.last_insert_rowid(),
            level,
            message: message.to_owned(),
            data: data.map(str::to_owned),
            created_at,
        })
    }

    pub async fn list_events(&self, limit: i64) -> edge_core::Result<Vec<Event>> {
        let limit = limit.clamp(1, 500);
        sqlx::query("SELECT * FROM events ORDER BY id DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .into_iter()
            .map(row_to_event)
            .collect()
    }

    async fn reject_duplicates(&self, mapping: &Mapping) -> edge_core::Result<()> {
        let rows = sqlx::query(
            "SELECT id, public_ip, edge_private_ip, target_ip FROM mappings WHERE id <> ?",
        )
        .bind(mapping.id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?;

        for row in rows {
            let existing_id: String = row.get("id");
            if let Some(public_ip) = mapping.public_ip {
                let existing_public_ip: Option<String> = row.get("public_ip");
                if existing_public_ip.as_deref() == Some(&public_ip.to_string()) {
                    return Err(EdgeCoreError::DuplicatePublicIp(public_ip));
                }
            }

            let edge_private_ip: String = row.get("edge_private_ip");
            if edge_private_ip == mapping.edge_private_ip.to_string() {
                return Err(EdgeCoreError::DuplicateEdgePrivateIp(
                    mapping.edge_private_ip,
                ));
            }

            let target_ip: String = row.get("target_ip");
            if target_ip == mapping.target_ip.to_string() {
                return Err(EdgeCoreError::DuplicateTargetIp(mapping.target_ip));
            }

            if existing_id == mapping.id.as_str() {
                return Err(EdgeCoreError::DuplicateMappingId(mapping.id.clone()));
            }
        }
        Ok(())
    }
}

fn row_to_mapping(row: sqlx::sqlite::SqliteRow) -> edge_core::Result<Mapping> {
    let id: String = row.get("id");
    let public_ip: Option<String> = row.get("public_ip");
    let target_port: Option<i64> = row.get("target_port");
    let target_port = match target_port {
        Some(port) if (1..=u16::MAX as i64).contains(&port) => Some(port as u16),
        Some(port) => {
            return Err(EdgeCoreError::store(format!(
                "invalid target_port in database: {port}"
            )))
        }
        None => None,
    };

    Ok(Mapping {
        id: MappingId::from_str(&id)?,
        name: row.get("name"),
        public_ip: parse_optional_ip(public_ip)?,
        oci_public_ip_ocid: row.get("oci_public_ip_ocid"),
        edge_private_ip: parse_ip(row.get::<String, _>("edge_private_ip"))?,
        oci_private_ip_ocid: row.get("oci_private_ip_ocid"),
        target_ip: parse_ip(row.get::<String, _>("target_ip"))?,
        target_port,
        protocol: enum_from_string(row.get::<String, _>("protocol"))?,
        mode: enum_from_string(row.get::<String, _>("mode"))?,
        enabled: row.get("enabled"),
        status: enum_from_string(row.get::<String, _>("status"))?,
        last_error: row.get("last_error"),
        health_status: row.get("health_status"),
        last_checked_at: parse_optional_time(row.get("last_checked_at"))?,
        created_at: parse_time(row.get::<String, _>("created_at"))?,
        updated_at: parse_time(row.get::<String, _>("updated_at"))?,
    })
}

fn row_to_generation(row: sqlx::sqlite::SqliteRow) -> edge_core::Result<Generation> {
    Ok(Generation {
        id: row.get("id"),
        status: enum_from_string(row.get("status"))?,
        nftables_config: row.get("nftables_config"),
        created_at: parse_time(row.get("created_at"))?,
        applied_at: parse_optional_time(row.get("applied_at"))?,
        error: row.get("error"),
    })
}

fn row_to_event(row: sqlx::sqlite::SqliteRow) -> edge_core::Result<Event> {
    Ok(Event {
        id: row.get("id"),
        level: enum_from_string(row.get("level"))?,
        message: row.get("message"),
        data: row.get("data"),
        created_at: parse_time(row.get("created_at"))?,
    })
}

fn parse_ip(value: String) -> edge_core::Result<Ipv4Addr> {
    value
        .parse()
        .map_err(|error| EdgeCoreError::store(format!("decode IPv4 address {value}: {error}")))
}

fn parse_optional_ip(value: Option<String>) -> edge_core::Result<Option<Ipv4Addr>> {
    value.map(parse_ip).transpose()
}

fn enum_string<T: serde::Serialize>(value: &T) -> edge_core::Result<String> {
    serde_json::to_value(value)
        .map_err(|error| EdgeCoreError::store(format!("encode enum: {error}")))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| EdgeCoreError::store("enum did not encode as string"))
}

fn enum_from_string<T: serde::de::DeserializeOwned>(value: String) -> edge_core::Result<T> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|error| EdgeCoreError::store(format!("decode enum: {error}")))
}

fn format_time(value: OffsetDateTime) -> edge_core::Result<String> {
    value
        .format(&Rfc3339)
        .map_err(|error| EdgeCoreError::store(format!("format time: {error}")))
}

fn format_optional_time(value: Option<OffsetDateTime>) -> edge_core::Result<Option<String>> {
    value.map(format_time).transpose()
}

fn parse_time(value: String) -> edge_core::Result<OffsetDateTime> {
    OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|error| EdgeCoreError::store(format!("parse time {value}: {error}")))
}

fn parse_optional_time(value: Option<String>) -> edge_core::Result<Option<OffsetDateTime>> {
    value.map(parse_time).transpose()
}

fn sql_error(error: sqlx::Error) -> EdgeCoreError {
    EdgeCoreError::store(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            None,
            "10.0.0.101".parse().unwrap(),
            "192.168.20.42".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn migrates_and_round_trips_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::connect(dir.path().join("state.sqlite"))
            .await
            .unwrap();
        store.set_edge_config(&config()).await.unwrap();
        let mapping = mapping();
        let id = mapping.id.clone();

        store.insert_mapping(&mapping).await.unwrap();

        assert_eq!(store.get_mapping(&id).await.unwrap(), mapping);
        assert_eq!(store.list_mappings().await.unwrap().len(), 1);
        assert_eq!(store.delete_mapping(&id).await.unwrap().id, id);
        assert!(matches!(
            store.get_mapping(&id).await.unwrap_err(),
            EdgeCoreError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn rejects_duplicate_static_targets() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::connect(dir.path().join("state.sqlite"))
            .await
            .unwrap();
        store.set_edge_config(&config()).await.unwrap();
        let first = mapping();
        let mut second = mapping();
        second.id = MappingId::new();
        second.edge_private_ip = "10.0.0.102".parse().unwrap();

        store.insert_mapping(&first).await.unwrap();
        let err = store.insert_mapping(&second).await.unwrap_err();

        assert_eq!(
            err,
            EdgeCoreError::DuplicateTargetIp("192.168.20.42".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn updates_oci_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::connect(dir.path().join("state.sqlite"))
            .await
            .unwrap();
        store.set_edge_config(&config()).await.unwrap();
        let mut mapping = mapping();
        let id = mapping.id.clone();
        store.insert_mapping(&mapping).await.unwrap();

        mapping.public_ip = Some("152.1.2.3".parse().unwrap());
        mapping.oci_public_ip_ocid = Some("ocid1.publicip.x".to_owned());
        mapping.oci_private_ip_ocid = Some("ocid1.privateip.x".to_owned());
        store.update_mapping(&mapping).await.unwrap();

        let stored = store.get_mapping(&id).await.unwrap();
        assert_eq!(stored.public_ip, Some("152.1.2.3".parse().unwrap()));
        assert_eq!(
            stored.oci_public_ip_ocid.as_deref(),
            Some("ocid1.publicip.x")
        );
    }

    #[tokio::test]
    async fn records_generation_and_event() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::connect(dir.path().join("state.sqlite"))
            .await
            .unwrap();

        let generation = store
            .record_generation(
                GenerationStatus::Validated,
                "table ip edge_nat {}",
                None,
                None,
            )
            .await
            .unwrap();
        let event = store
            .record_event(EventLevel::Info, "validated nft", Some("{\"ok\":true}"))
            .await
            .unwrap();

        assert_eq!(generation.id, 1);
        assert_eq!(
            store.get_generation(1).await.unwrap().status,
            GenerationStatus::Validated
        );
        assert_eq!(event.id, 1);
        assert_eq!(store.list_events(10).await.unwrap().len(), 1);
    }
}
