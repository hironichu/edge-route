use std::net::Ipv4Addr;

use thiserror::Error;

use crate::mapping::MappingId;

pub type Result<T> = std::result::Result<T, EdgeCoreError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EdgeCoreError {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("mapping not found: {0}")]
    NotFound(MappingId),

    #[error("public IP already mapped: {0}")]
    DuplicatePublicIp(Ipv4Addr),

    #[error("edge private IP already mapped: {0}")]
    DuplicateEdgePrivateIp(Ipv4Addr),

    #[error("target IP already mapped: {0}")]
    DuplicateTargetIp(Ipv4Addr),

    #[error("mapping id already exists: {0}")]
    DuplicateMappingId(MappingId),

    #[error("store error: {0}")]
    Store(String),
}

impl EdgeCoreError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn store(message: impl Into<String>) -> Self {
        Self::Store(message.into())
    }
}
