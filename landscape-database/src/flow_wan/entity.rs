use crate::repository::UpdateActiveModel;
use landscape_common::flow::service::FlowWanServiceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBTimestamp;

pub type FlowWanServiceConfigModel = Model;
pub type FlowWanServiceConfigEntity = Entity;
pub type FlowWanServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "flow_wan_service_configs")]
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

impl From<Model> for FlowWanServiceConfig {
    fn from(entity: Model) -> Self {
        FlowWanServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
        }
    }
}

impl From<FlowWanServiceConfig> for ActiveModel {
    fn from(val: FlowWanServiceConfig) -> Self {
        let mut active = ActiveModel {
            iface_name: Set(val.iface_name.clone()),
            ..Default::default()
        };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for FlowWanServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.update_at = Set(self.update_at);
    }
}
