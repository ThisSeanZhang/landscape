use landscape_common::wan_link::WanLinkConfig;
use sea_orm::DatabaseConnection;

use super::entity::{WanLinkConfigActiveModel, WanLinkConfigEntity, WanLinkConfigModel};
use crate::DBId;

#[derive(Clone)]
pub struct WanLinkRepository {
    db: DatabaseConnection,
}

impl WanLinkRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    WanLinkRepository,
    WanLinkConfigModel,
    WanLinkConfigEntity,
    WanLinkConfigActiveModel,
    WanLinkConfig,
    DBId
);

crate::impl_trivial_validator!(WanLinkRepository, WanLinkConfig);
