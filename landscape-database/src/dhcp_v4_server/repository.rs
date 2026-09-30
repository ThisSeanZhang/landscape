use landscape_common::lan_service::lan_dhcpv4::config::DHCPv4ServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    DHCPv4ServiceConfigActiveModel, DHCPv4ServiceConfigEntity, DHCPv4ServiceConfigModel,
};

#[derive(Clone)]
pub struct DHCPv4ServerRepository {
    db: DatabaseConnection,
}

impl DHCPv4ServerRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn is_ip_in_subnet(&self, iface_name: String, ip: u32) -> Result<bool, String> {
        use crate::dhcp_v4_server::entity::Column;
        use crate::repository::Repository;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let exists: Option<DHCPv4ServiceConfigModel> = DHCPv4ServiceConfigEntity::find()
            .filter(Column::IfaceName.eq(iface_name))
            .filter(Column::NetworkStart.lte(ip))
            .filter(Column::NetworkEnd.gte(ip))
            .one(self.db())
            .await
            .map_err(|e| e.to_string())?;

        Ok(exists.is_some())
    }

    pub async fn check_ip_range_conflict(
        &self,
        iface_name: String,
        server_ip: std::net::Ipv4Addr,
        mask: u8,
    ) -> Result<Option<String>, String> {
        use crate::dhcp_v4_server::entity::Column;
        use crate::repository::Repository;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let ip_u32 = u32::from(server_ip);
        let mask_u32 = if mask == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - mask) };
        let network_start = ip_u32 & mask_u32;
        let network_end = network_start | !mask_u32;

        let conflict: Option<DHCPv4ServiceConfigModel> = DHCPv4ServiceConfigEntity::find()
            .filter(Column::IfaceName.ne(iface_name))
            .filter(Column::NetworkStart.lte(network_end))
            .filter(Column::NetworkEnd.gte(network_start))
            .one(self.db())
            .await
            .map_err(|e| e.to_string())?;

        Ok(conflict.map(|c| c.iface_name))
    }
}

crate::impl_repository!(
    DHCPv4ServerRepository,
    DHCPv4ServiceConfigModel,
    DHCPv4ServiceConfigEntity,
    DHCPv4ServiceConfigActiveModel,
    DHCPv4ServiceConfig,
    String
);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<DHCPv4ServiceConfig>
    for DHCPv4ServerRepository
{
    async fn check_zone(
        &self,
        config: &DHCPv4ServiceConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        crate::validator::ZoneChecker::new(self.db.clone()).check(config).await
    }

    async fn validate_cross(
        &self,
        config: &DHCPv4ServiceConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        if let Some(conflict_iface) = self
            .check_ip_range_conflict(
                config.iface_name.clone(),
                config.config.server_ip_addr,
                config.config.network_mask,
            )
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "DHCP subnet on '{conflict_iface}' overlaps with this interface's subnet"
                ),
            });
        }
        Ok(())
    }
}
