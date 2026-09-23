use landscape_common::wan_service::nat::config::NatServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{NatServiceConfigActiveModel, NatServiceConfigEntity, NatServiceConfigModel};

#[derive(Clone)]
pub struct NatServiceRepository {
    db: DatabaseConnection,
}

impl NatServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    NatServiceRepository,
    NatServiceConfigModel,
    NatServiceConfigEntity,
    NatServiceConfigActiveModel,
    NatServiceConfig,
    String
);
