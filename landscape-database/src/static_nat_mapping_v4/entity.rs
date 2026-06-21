use landscape_common::iface::nat::{StaticNatMappingV4Config, StaticNatV4Target};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBId;
use crate::DBJson;
use crate::DBTimestamp;

pub type StaticNatMappingV4ConfigModel = Model;
pub type StaticNatMappingV4ConfigEntity = Entity;
pub type StaticNatMappingV4ConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "static_nat_mapping_v4_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub enable: bool,
    pub remark: String,
    pub wan_iface_name: Option<String>,
    pub mapping_pair_ports: DBJson,
    pub lan_target: Option<DBJson>,
    #[sea_orm(column_name = "lan_ipv4")]
    pub lan_ipv4: Option<String>,
    #[sea_orm(column_name = "l4_protocols")]
    pub l4_protocols: DBJson,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for StaticNatMappingV4Config {
    fn from(model: Model) -> Self {
        let lan_ipv4 = model.lan_ipv4.and_then(|e| e.parse().ok());
        StaticNatMappingV4Config {
            id: model.id,
            enable: model.enable,
            remark: model.remark,
            mapping_pair_ports: serde_json::from_value(model.mapping_pair_ports).unwrap(),
            wan_iface_name: model.wan_iface_name,
            lan_target: model
                .lan_target
                .and_then(|target| serde_json::from_value(target).ok())
                .or_else(|| lan_ipv4.map(|ip| StaticNatV4Target::address(ip))),
            l4_protocols: serde_json::from_value(model.l4_protocols).unwrap(),
            update_at: model.update_at,
        }
    }
}

impl Into<ActiveModel> for StaticNatMappingV4Config {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        crate::repository::UpdateActiveModel::<ActiveModel>::update(self, &mut active);
        active
    }
}

impl crate::repository::UpdateActiveModel<ActiveModel> for StaticNatMappingV4Config {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.remark = Set(self.remark);
        active.wan_iface_name = Set(self.wan_iface_name);
        active.mapping_pair_ports = Set(serde_json::to_value(&self.mapping_pair_ports).unwrap());
        let (lan_ipv4, lan_target) = address_from_target(self.lan_target.as_ref());
        active.lan_target = Set(lan_target);
        active.lan_ipv4 = Set(lan_ipv4.map(|ip| ip.to_string()));
        active.l4_protocols = Set(serde_json::to_value(&self.l4_protocols).unwrap());
        active.update_at = Set(self.update_at);
    }
}

fn address_from_target(
    lan_target: Option<&StaticNatV4Target>,
) -> (Option<std::net::Ipv4Addr>, Option<serde_json::Value>) {
    match lan_target {
        Some(StaticNatV4Target::Address { ipv4 }) => {
            (Some(*ipv4), Some(serde_json::json!({"t": "address", "ipv4": ipv4.to_string()})))
        }
        Some(StaticNatV4Target::Local) => {
            (Some(std::net::Ipv4Addr::UNSPECIFIED), Some(serde_json::json!({"t": "local"})))
        }
        Some(StaticNatV4Target::Device { device_id }) => {
            (None, Some(serde_json::json!({"t": "device", "device_id": device_id.to_string()})))
        }
        None => (None, None),
    }
}
