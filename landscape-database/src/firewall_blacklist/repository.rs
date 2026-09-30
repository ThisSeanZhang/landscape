use landscape_common::wan_service::firewall::blacklist::FirewallBlacklistConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    FirewallBlacklistConfigActiveModel, FirewallBlacklistConfigEntity, FirewallBlacklistConfigModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct FirewallBlacklistRepository {
    db: DatabaseConnection,
}

impl FirewallBlacklistRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    FirewallBlacklistRepository,
    FirewallBlacklistConfigModel,
    FirewallBlacklistConfigEntity,
    FirewallBlacklistConfigActiveModel,
    FirewallBlacklistConfig,
    DBId
);

crate::impl_trivial_validator!(FirewallBlacklistRepository, FirewallBlacklistConfig);
