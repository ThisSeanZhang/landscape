use crate::repository::UpdateActiveModel;
use landscape_common::lan_service::lan_ipv6::LanIPv6ServiceConfigV2;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBJson, DBTimestamp};

pub type LanIPv6ServiceConfigV2Model = Model;
pub type LanIPv6ServiceConfigV2Entity = Entity;
pub type LanIPv6ServiceConfigV2ActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "lan_ipv6_service_configs_v2")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,
    pub config: DBJson,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for LanIPv6ServiceConfigV2 {
    fn from(entity: Model) -> Self {
        LanIPv6ServiceConfigV2 {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
            config: serde_json::from_value(entity.config).unwrap(),
        }
    }
}

impl From<LanIPv6ServiceConfigV2> for ActiveModel {
    fn from(val: LanIPv6ServiceConfigV2) -> Self {
        let mut active = ActiveModel {
            iface_name: Set(val.iface_name.clone()),
            ..Default::default()
        };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for LanIPv6ServiceConfigV2 {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.update_at = Set(self.update_at);
        active.config = Set(serde_json::to_value(self.config).unwrap());
    }
}
