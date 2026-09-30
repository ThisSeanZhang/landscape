use landscape_common::lan_service::ap::WifiServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    WifiServiceConfigActiveModel, WifiServiceConfigEntity, WifiServiceConfigModel,
};

#[derive(Clone)]
pub struct WifiServiceRepository {
    db: DatabaseConnection,
}

impl WifiServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    WifiServiceRepository,
    WifiServiceConfigModel,
    WifiServiceConfigEntity,
    WifiServiceConfigActiveModel,
    WifiServiceConfig,
    String
);

crate::impl_zone_validator!(WifiServiceRepository, WifiServiceConfig);
