use crate::repository::UpdateActiveModel;
use landscape_common::config_service::static_nat::config::{
    StaticNatMappingConfig, StaticNatTarget,
};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBId;
use crate::DBJson;
use crate::DBTimestamp;

pub type StaticNatMappingConfigModel = Model;
pub type StaticNatMappingConfigEntity = Entity;
pub type StaticNatMappingConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "static_nat_mapping_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    /// Whether this mapping is enabled
    pub enable: bool,

    pub remark: String,

    /// Optional name of the WAN interface this rule applies to
    pub wan_iface_name: Option<String>,

    /// Port Pair for the NAT rule
    pub mapping_pair_ports: DBJson,

    pub lan_target: Option<DBJson>,

    /// Internal IP address to forward traffic to
    /// If set to `UNSPECIFIED` (0.0.0.0 or ::), the mapping targets the router itself
    #[sea_orm(column_name = "lan_ipv4")]
    pub lan_ipv4: Option<String>,

    #[sea_orm(column_name = "lan_ipv6")]
    pub lan_ipv6: Option<String>,

    /// Ipv4 Layer 4 protocol (TCP / UDP)
    #[sea_orm(column_name = "ipv4_l4_protocol")]
    pub ipv4_l4_protocol: DBJson,

    /// Ipv6 Layer 4 protocol (TCP / UDP)
    #[sea_orm(column_name = "ipv6_l4_protocol")]
    pub ipv6_l4_protocol: DBJson,

    /// Last update timestamp
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for StaticNatMappingConfig {
    fn from(model: Model) -> Self {
        let lan_ipv4 = model.lan_ipv4.map(|e| e.parse().ok()).unwrap_or(None);
        let lan_ipv6 = model.lan_ipv6.map(|e| e.parse().ok()).unwrap_or(None);
        StaticNatMappingConfig {
            id: model.id,
            enable: model.enable,
            remark: model.remark,
            mapping_pair_ports: serde_json::from_value(model.mapping_pair_ports).unwrap(),
            wan_iface_name: model.wan_iface_name,
            lan_target: model
                .lan_target
                .and_then(|target| serde_json::from_value(target).ok())
                .or_else(|| Some(StaticNatTarget::address(lan_ipv4, lan_ipv6))),
            ipv4_l4_protocol: serde_json::from_value(model.ipv4_l4_protocol).unwrap(),
            ipv6_l4_protocol: serde_json::from_value(model.ipv6_l4_protocol).unwrap(),
            update_at: model.update_at,
        }
    }
}

impl From<StaticNatMappingConfig> for ActiveModel {
    fn from(val: StaticNatMappingConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for StaticNatMappingConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.remark = Set(self.remark);
        active.wan_iface_name = Set(self.wan_iface_name);
        active.mapping_pair_ports = Set(serde_json::to_value(&self.mapping_pair_ports).unwrap());
        let (lan_ipv4, lan_ipv6) = address_fields_from_target(self.lan_target.as_ref());
        active.lan_target = Set(Some(
            serde_json::to_value(
                self.lan_target
                    .clone()
                    .unwrap_or_else(|| StaticNatTarget::address(lan_ipv4, lan_ipv6)),
            )
            .unwrap(),
        ));

        active.lan_ipv4 = Set(lan_ipv4.map(|ip| ip.to_string()));
        active.lan_ipv6 = Set(lan_ipv6.map(|ip| ip.to_string()));
        active.ipv4_l4_protocol = Set(serde_json::to_value(&self.ipv4_l4_protocol).unwrap());
        active.ipv6_l4_protocol = Set(serde_json::to_value(&self.ipv6_l4_protocol).unwrap());
        active.update_at = Set(self.update_at);
    }
}

fn address_fields_from_target(
    lan_target: Option<&StaticNatTarget>,
) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>) {
    match lan_target {
        Some(StaticNatTarget::Address { ipv4, ipv6 }) => (*ipv4, *ipv6),
        Some(StaticNatTarget::Local) => {
            (Some(std::net::Ipv4Addr::UNSPECIFIED), Some(std::net::Ipv6Addr::UNSPECIFIED))
        }
        Some(StaticNatTarget::Device { .. }) | None => (None, None),
    }
}
