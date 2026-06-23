//! Core data model and state contracts for the edge router controller.

pub mod errors;
pub mod mapping;
pub mod state;
pub mod validation;

pub use errors::{EdgeCoreError, Result};
pub use mapping::{
    EdgeConfig, Mapping, MappingBackend, MappingId, MappingMode, MappingStatus, OciAuthMode,
    Protocol,
};
pub use state::{Event, EventLevel, Generation, GenerationStatus, InMemoryStateStore, StateStore};
