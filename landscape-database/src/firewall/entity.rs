use crate::repository::UpdateActiveModel;
use landscape_common::wan_service::firewall::service::FirewallServiceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBTimestamp;

pub type FirewallServiceConfigModel = Model;
pub type FirewallServiceConfigEntity = Entity;
pub type FirewallServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "firewall_service_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,

    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for FirewallServiceConfig {
    fn from(entity: Model) -> Self {
        FirewallServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
        }
    }
}

impl From<FirewallServiceConfig> for ActiveModel {
    fn from(val: FirewallServiceConfig) -> Self {
        let mut active = ActiveModel {
            iface_name: Set(val.iface_name.clone()),
            ..Default::default()
        };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for FirewallServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.update_at = Set(self.update_at);
    }
}
