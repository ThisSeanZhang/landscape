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
