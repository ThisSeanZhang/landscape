use landscape_common::iface::nat::{StaticNatMappingV6Config, StaticNatV6Target};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBId;
use crate::DBJson;
use crate::DBTimestamp;

pub type StaticNatMappingV6ConfigModel = Model;
pub type StaticNatMappingV6ConfigEntity = Entity;
pub type StaticNatMappingV6ConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "static_nat_mapping_v6_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub enable: bool,
    pub remark: String,
    pub wan_iface_name: Option<String>,
    pub mapping_pair_ports: DBJson,
    pub lan_target: Option<DBJson>,
    #[sea_orm(column_name = "lan_ipv6")]
    pub lan_ipv6: Option<String>,
    #[sea_orm(column_name = "l4_protocols")]
    pub l4_protocols: DBJson,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for StaticNatMappingV6Config {
    fn from(model: Model) -> Self {
        let lan_ipv6 = model.lan_ipv6.and_then(|e| e.parse().ok());
        StaticNatMappingV6Config {
            id: model.id,
            enable: model.enable,
            remark: model.remark,
            mapping_pair_ports: serde_json::from_value(model.mapping_pair_ports).unwrap(),
            wan_iface_name: model.wan_iface_name,
            lan_target: model
                .lan_target
                .and_then(|target| serde_json::from_value(target).ok())
                .or_else(|| lan_ipv6.map(|ip| StaticNatV6Target::address(ip))),
            l4_protocols: serde_json::from_value(model.l4_protocols).unwrap(),
            update_at: model.update_at,
        }
    }
}

impl Into<ActiveModel> for StaticNatMappingV6Config {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        crate::repository::UpdateActiveModel::<ActiveModel>::update(self, &mut active);
        active
    }
}

impl crate::repository::UpdateActiveModel<ActiveModel> for StaticNatMappingV6Config {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.remark = Set(self.remark);
        active.wan_iface_name = Set(self.wan_iface_name);
        active.mapping_pair_ports = Set(serde_json::to_value(&self.mapping_pair_ports).unwrap());
        let (lan_ipv6, lan_target) = address_from_target(self.lan_target.as_ref());
        active.lan_target = Set(lan_target);
        active.lan_ipv6 = Set(lan_ipv6.map(|ip| ip.to_string()));
        active.l4_protocols = Set(serde_json::to_value(&self.l4_protocols).unwrap());
        active.update_at = Set(self.update_at);
    }
}

fn address_from_target(
    lan_target: Option<&StaticNatV6Target>,
) -> (Option<std::net::Ipv6Addr>, Option<serde_json::Value>) {
    match lan_target {
        Some(StaticNatV6Target::Address { ipv6 }) => {
            (Some(*ipv6), Some(serde_json::json!({"t": "address", "ipv6": ipv6.to_string()})))
        }
        Some(StaticNatV6Target::Local) => {
            (Some(std::net::Ipv6Addr::UNSPECIFIED), Some(serde_json::json!({"t": "local"})))
        }
        Some(StaticNatV6Target::Device { device_id }) => {
            (None, Some(serde_json::json!({"t": "device", "device_id": device_id.to_string()})))
        }
        None => (None, None),
    }
}
