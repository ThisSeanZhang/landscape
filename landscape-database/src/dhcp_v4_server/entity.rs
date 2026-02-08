use landscape_common::{
    database::repository::UpdateActiveModel,
    dhcp::v4_server::config::{DHCPv4ServerConfig, DHCPv4ServiceConfig},
};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBJson, DBTimestamp};

pub type DHCPv4ServiceConfigModel = Model;
pub type DHCPv4ServiceConfigEntity = Entity;
pub type DHCPv4ServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dhcp_v4_server_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,

    pub ip_range_start: String,
    pub ip_range_end: Option<String>,

    pub server_ip_addr: String,
    pub network_mask: u8,
    pub network_start: u32,
    pub network_end: u32,

    pub address_lease_time: Option<u32>,

    pub mac_binding_records: DBJson,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for DHCPv4ServiceConfig {
    fn from(entity: Model) -> Self {
        let config = DHCPv4ServerConfig {
            ip_range_start: entity.ip_range_start.parse().expect("Invalid IP format"),
            ip_range_end: entity.ip_range_end.map(|ip| ip.parse().expect("Invalid IP format")),
            server_ip_addr: entity.server_ip_addr.parse().expect("Invalid IP format"),
            network_mask: entity.network_mask,
            address_lease_time: entity.address_lease_time,
            mac_binding_records: serde_json::from_value(entity.mac_binding_records).unwrap(),
        };
        DHCPv4ServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
            config,
        }
    }
}

impl Into<ActiveModel> for DHCPv4ServiceConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel {
            iface_name: Set(self.iface_name.clone()),
            ..Default::default()
        };
        update(self, &mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for DHCPv4ServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.ip_range_start = Set(self.config.ip_range_start.to_string());
        active.ip_range_end = Set(self.config.ip_range_end.map(|ip| ip.to_string()));
        active.server_ip_addr = Set(self.config.server_ip_addr.to_string());
        active.network_mask = Set(self.config.network_mask);
        let ip_u32 = u32::from(self.config.server_ip_addr);
        let mask_u32 = if self.config.network_mask == 0 {
            0
        } else {
            0xFFFFFFFFu32 << (32 - self.config.network_mask)
        };
        active.network_start = Set(ip_u32 & mask_u32);
        active.network_end = Set((ip_u32 & mask_u32) | !mask_u32);
        active.address_lease_time = Set(self.config.address_lease_time);
        active.mac_binding_records = Set(serde_json::to_value(&self.config.mac_binding_records)
            .unwrap_or(serde_json::Value::Array(vec![])));
        active.update_at = Set(self.update_at);
    }
}

pub(crate) fn update(config: DHCPv4ServiceConfig, active: &mut ActiveModel) {
    active.enable = Set(config.enable);
    active.ip_range_start = Set(config.config.ip_range_start.to_string());
    active.ip_range_end = Set(config.config.ip_range_end.map(|ip| ip.to_string()));
    active.server_ip_addr = Set(config.config.server_ip_addr.to_string());
    active.network_mask = Set(config.config.network_mask);
    let ip_u32 = u32::from(config.config.server_ip_addr);
    let mask_u32 = if config.config.network_mask == 0 {
        0
    } else {
        0xFFFFFFFFu32 << (32 - config.config.network_mask)
    };
    active.network_start = Set(ip_u32 & mask_u32);
    active.network_end = Set((ip_u32 & mask_u32) | !mask_u32);
    active.address_lease_time = Set(config.config.address_lease_time);
    active.mac_binding_records = Set(serde_json::to_value(&config.config.mac_binding_records)
        .unwrap_or(serde_json::Value::Array(vec![])));
    active.update_at = Set(config.update_at);
}
