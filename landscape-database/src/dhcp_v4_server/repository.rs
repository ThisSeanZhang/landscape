use landscape_common::{
    database::{repository::Repository, LandscapeDBTrait, LandscapeServiceDBTrait},
    dhcp::v4_server::config::DHCPv4ServiceConfig,
};
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

    pub async fn is_ip_in_range(&self, iface_name: String, ip: u32) -> Result<bool, String> {
        use crate::dhcp_v4_server::entity::Column;
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let exists: Option<DHCPv4ServiceConfigModel> = DHCPv4ServiceConfigEntity::find()
            .filter(Column::IfaceName.eq(iface_name))
            .filter(Column::NetworkStart.lte(ip))
            .filter(Column::NetworkEnd.gte(ip))
            .one(&self.db)
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
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

        let ip_u32 = u32::from(server_ip);
        let mask_u32 = if mask == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - mask) };
        let network_start = ip_u32 & mask_u32;
        let network_end = network_start | !mask_u32;

        // 查找与指定范围有重叠的配置（排除自己）
        // 重叠条件：A的开始 <= B的结束 && B的开始 <= A的结束
        let conflict: Option<DHCPv4ServiceConfigModel> = DHCPv4ServiceConfigEntity::find()
            .filter(Column::IfaceName.ne(iface_name))
            .filter(Column::NetworkStart.lte(network_end))
            .filter(Column::NetworkEnd.gte(network_start))
            .one(&self.db)
            .await
            .map_err(|e| e.to_string())?;

        Ok(conflict.map(|c| c.iface_name))
    }
}
#[async_trait::async_trait]
impl LandscapeServiceDBTrait for DHCPv4ServerRepository {}

#[async_trait::async_trait]
impl LandscapeDBTrait for DHCPv4ServerRepository {}

#[async_trait::async_trait]
impl Repository for DHCPv4ServerRepository {
    type Model = DHCPv4ServiceConfigModel;
    type Entity = DHCPv4ServiceConfigEntity;
    type ActiveModel = DHCPv4ServiceConfigActiveModel;
    type Data = DHCPv4ServiceConfig;
    type Id = String;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}

// impl LandscapeDBStore<String> for DHCPv4ServiceConfig {
//     fn get_id(&self) -> String {
//         self.iface_name.clone()
//     }
// }
