pub mod error;
pub mod repository;
pub mod store;

use crate::{config::FlowId, error::LdError};

/// Clean storage interface, decoupled from any ORM types
#[async_trait::async_trait]
pub trait LandscapeStore: Send + Sync {
    type Data: Send + Sync + std::fmt::Debug;
    type Id: Send + Sync + std::fmt::Debug;

    async fn set(&self, config: Self::Data) -> Result<Self::Data, LdError>;
    async fn list(&self) -> Result<Vec<Self::Data>, LdError>;
    async fn delete(&self, id: Self::Id) -> Result<(), LdError>;
    async fn find_by_id(&self, id: Self::Id) -> Result<Option<Self::Data>, LdError>;
    async fn find_by_ids(&self, ids: Vec<Self::Id>) -> Vec<Self::Data>;

    /// Read-only conflict check.
    /// - Record missing → Ok(None)
    /// - Record exists and `update_at` matches → Ok(Some(old config))
    /// - Record exists but `update_at` differs → Err(ConfigConflict)
    async fn check_conflict(&self, config: &Self::Data) -> Result<Option<Self::Data>, LdError>;

    /// Optimistic-lock set: check `update_at`, refresh the timestamp, then write
    async fn checked_set(&self, config: Self::Data) -> Result<Self::Data, LdError>;
}

/// Storage interface with Flow-based queries
#[async_trait::async_trait]
pub trait LandscapeFlowStore: LandscapeStore {
    async fn find_by_flow_id(&self, flow_id: FlowId) -> Result<Vec<Self::Data>, LdError>;
}
