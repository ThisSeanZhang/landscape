use crate::repository::UpdateActiveModel;
use landscape_common::wan_service::ip_config::IfaceIpServiceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBJson, DBTimestamp};

pub type IfaceIpServiceConfigModel = Model;
pub type IfaceIpServiceConfigEntity = Entity;
pub type IfaceIpServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "iface_ip_service_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,
    pub ip_model: DBJson,

    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for IfaceIpServiceConfig {
    fn from(entity: Model) -> Self {
        IfaceIpServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            ip_model: serde_json::from_value(entity.ip_model).unwrap(),
            update_at: entity.update_at,
        }
    }
}

impl From<IfaceIpServiceConfig> for ActiveModel {
    fn from(val: IfaceIpServiceConfig) -> Self {
        let mut active = ActiveModel {
            iface_name: Set(val.iface_name.clone()),
            ..Default::default()
        };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for IfaceIpServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.ip_model = Set(serde_json::to_value(self.ip_model).unwrap());
        active.update_at = Set(self.update_at)
    }
}
