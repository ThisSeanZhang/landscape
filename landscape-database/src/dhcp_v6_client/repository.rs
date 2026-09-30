use landscape_common::wan_service::ipv6_pd::IPV6PDServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    DHCPv6ClientConfigActiveModel, DHCPv6ClientConfigEntity, DHCPv6ClientConfigModel,
};

#[derive(Clone)]
pub struct DHCPv6ClientRepository {
    db: DatabaseConnection,
}

impl DHCPv6ClientRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    DHCPv6ClientRepository,
    DHCPv6ClientConfigModel,
    DHCPv6ClientConfigEntity,
    DHCPv6ClientConfigActiveModel,
    IPV6PDServiceConfig,
    String
);

crate::impl_zone_validator!(DHCPv6ClientRepository, IPV6PDServiceConfig);
