use landscape_common::wan_service::firewall::service::FirewallServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    FirewallServiceConfigActiveModel, FirewallServiceConfigEntity, FirewallServiceConfigModel,
};

#[derive(Clone)]
pub struct FirewallServiceRepository {
    db: DatabaseConnection,
}

impl FirewallServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    FirewallServiceRepository,
    FirewallServiceConfigModel,
    FirewallServiceConfigEntity,
    FirewallServiceConfigActiveModel,
    FirewallServiceConfig,
    String
);

crate::impl_zone_validator!(FirewallServiceRepository, FirewallServiceConfig);
