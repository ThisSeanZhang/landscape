use crate::repository::UpdateActiveModel;
use landscape_common::{
    config_service::iface::CreateDevType, config_service::iface::IfaceZoneType,
    config_service::iface::NetworkIfaceConfig, config_service::iface::WifiMode,
};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBJson, DBTimestamp};

pub type NetIfaceConfigModel = Model;
pub type NetIfaceConfigEntity = Entity;
pub type NetIfaceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "net_iface_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub create_dev_type: CreateDevType,
    pub controller_name: Option<String>,
    pub zone_type: IfaceZoneType,
    pub enable_in_boot: bool,
    pub wifi_mode: WifiMode,
    pub xps_rps: Option<DBJson>,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for NetworkIfaceConfig {
    fn from(entity: Model) -> Self {
        NetworkIfaceConfig {
            name: entity.name,
            create_dev_type: entity.create_dev_type,
            controller_name: entity.controller_name,
            zone_type: entity.zone_type,
            enable_in_boot: entity.enable_in_boot,
            wifi_mode: entity.wifi_mode,
            xps_rps: entity.xps_rps.and_then(|val| serde_json::from_value(val).ok()),
            update_at: entity.update_at,
        }
    }
}

impl From<NetworkIfaceConfig> for ActiveModel {
    fn from(val: NetworkIfaceConfig) -> Self {
        let mut active = ActiveModel { name: Set(val.name.clone()), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for NetworkIfaceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.create_dev_type = Set(self.create_dev_type);
        active.controller_name = Set(self.controller_name);
        active.zone_type = Set(self.zone_type);
        active.enable_in_boot = Set(self.enable_in_boot);
        active.wifi_mode = Set(self.wifi_mode);
        active.xps_rps = Set(self.xps_rps.and_then(|val| serde_json::to_value(&val).ok()));
        active.update_at = Set(self.update_at);
    }
}
