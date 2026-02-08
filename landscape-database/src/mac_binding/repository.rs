use landscape_common::{
    database::{repository::Repository, LandscapeDBTrait, LandscapeServiceDBTrait},
    error::LdError,
    mac_binding::IpMacBinding,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::net::Ipv4Addr;

use crate::DBId;

use super::entity::{Column, IpMacBindingActiveModel, IpMacBindingEntity, IpMacBindingModel};

#[derive(Clone)]
pub struct IpMacBindingRepository {
    db: DatabaseConnection,
}

impl IpMacBindingRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_mac(&self, mac: String) -> Result<Option<IpMacBinding>, String> {
        let model = IpMacBindingEntity::find()
            .filter(Column::Mac.eq(mac))
            .one(self.db())
            .await
            .map_err(|e| e.to_string())?;

        Ok(model.map(|m| m.into()))
    }

    pub async fn find_by_iface(&self, iface_name: String) -> Result<Vec<IpMacBinding>, LdError> {
        let models = IpMacBindingEntity::find()
            .filter(Column::IfaceName.eq(iface_name))
            .all(self.db())
            .await?;
        Ok(models.into_iter().map(|m| m.into()).collect())
    }

    pub async fn find_dhcp_bindings(
        &self,
        iface_name: String,
        server_ip: Ipv4Addr,
        mask: u8,
    ) -> Result<Vec<IpMacBinding>, LdError> {
        let server_ip_u32 = u32::from(server_ip);
        let mask_u32 = if mask == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - mask) };
        let network_start = server_ip_u32 & mask_u32;
        let network_end = network_start | !mask_u32;

        let models = IpMacBindingEntity::find()
            .filter(
                sea_orm::Condition::all()
                    .add(
                        sea_orm::Condition::any()
                            .add(Column::IfaceName.eq(iface_name))
                            .add(Column::IfaceName.is_null()),
                    )
                    .add(Column::Ipv4Int.gte(network_start))
                    .add(Column::Ipv4Int.lte(network_end)),
            )
            .all(self.db())
            .await?;

        Ok(models.into_iter().map(|m| m.into()).collect())
    }
}

#[async_trait::async_trait]
impl LandscapeServiceDBTrait for IpMacBindingRepository {}

#[async_trait::async_trait]
impl LandscapeDBTrait for IpMacBindingRepository {}

#[async_trait::async_trait]
impl Repository for IpMacBindingRepository {
    type Model = IpMacBindingModel;
    type Entity = IpMacBindingEntity;
    type ActiveModel = IpMacBindingActiveModel;
    type Data = IpMacBinding;
    type Id = DBId;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
