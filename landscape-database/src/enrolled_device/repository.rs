use landscape_common::{
    database::{repository::Repository, LandscapeDBTrait, LandscapeServiceDBTrait},
    enrolled_device::EnrolledDevice,
    error::LdError,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::net::Ipv4Addr;

use crate::DBId;

use super::entity::{Column, EnrolledDeviceActiveModel, EnrolledDeviceEntity, EnrolledDeviceModel};

#[derive(Clone)]
pub struct EnrolledDeviceRepository {
    db: DatabaseConnection,
}

impl EnrolledDeviceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_ipv4(&self, ipv4: Ipv4Addr) -> Result<Option<EnrolledDevice>, LdError> {
        let ip_u32 = u32::from(ipv4);
        let model =
            EnrolledDeviceEntity::find().filter(Column::Ipv4Int.eq(ip_u32)).one(self.db()).await?;
        Ok(model.map(|m| m.into()))
    }

    pub async fn find_by_mac(&self, mac: String) -> Result<Option<EnrolledDevice>, String> {
        let model = EnrolledDeviceEntity::find()
            .filter(Column::Mac.eq(mac))
            .one(self.db())
            .await
            .map_err(|e| e.to_string())?;

        Ok(model.map(|m| m.into()))
    }

    pub async fn find_by_iface(&self, iface_name: String) -> Result<Vec<EnrolledDevice>, LdError> {
        let models = EnrolledDeviceEntity::find()
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
    ) -> Result<Vec<EnrolledDevice>, LdError> {
        let server_ip_u32 = u32::from(server_ip);
        let mask_u32 = if mask == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - mask) };
        let network_start = server_ip_u32 & mask_u32;
        let network_end = network_start | !mask_u32;

        let models = EnrolledDeviceEntity::find()
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

    /// 查找属于指定网卡，但 IP 不在给定范围内的绑定记录
    pub async fn find_out_of_range_bindings(
        &self,
        iface_name: String,
        server_ip: std::net::Ipv4Addr,
        mask: u8,
    ) -> Result<Vec<EnrolledDevice>, LdError> {
        let server_ip_u32 = u32::from(server_ip);
        let mask_u32 = if mask == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - mask) };
        let network_start = server_ip_u32 & mask_u32;
        let network_end = network_start | !mask_u32;

        let models = EnrolledDeviceEntity::find()
            .filter(
                sea_orm::Condition::all().add(Column::IfaceName.eq(iface_name)).add(
                    sea_orm::Condition::any()
                        .add(Column::Ipv4Int.lt(network_start))
                        .add(Column::Ipv4Int.gt(network_end))
                        .add(Column::Ipv4Int.is_null()),
                ),
            )
            .all(self.db())
            .await?;

        Ok(models.into_iter().map(|m| m.into()).collect())
    }
}

#[async_trait::async_trait]
impl LandscapeServiceDBTrait for EnrolledDeviceRepository {}

#[async_trait::async_trait]
impl LandscapeDBTrait for EnrolledDeviceRepository {}

#[async_trait::async_trait]
impl Repository for EnrolledDeviceRepository {
    type Model = EnrolledDeviceModel;
    type Entity = EnrolledDeviceEntity;
    type ActiveModel = EnrolledDeviceActiveModel;
    type Data = EnrolledDevice;
    type Id = DBId;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
