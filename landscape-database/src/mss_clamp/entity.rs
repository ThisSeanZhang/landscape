use crate::repository::UpdateActiveModel;
use landscape_common::wan_service::mss_clamp::MSSClampServiceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBTimestamp;

pub type MSSClampServiceConfigModel = Model;
pub type MSSClampServiceConfigEntity = Entity;
pub type MSSClampServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "mss_clamp_service_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,
    pub clamp_size: u16,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for MSSClampServiceConfig {
    fn from(entity: Model) -> Self {
        MSSClampServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            clamp_size: entity.clamp_size,
            update_at: entity.update_at,
        }
    }
}

impl From<MSSClampServiceConfig> for ActiveModel {
    fn from(val: MSSClampServiceConfig) -> Self {
        let mut active = ActiveModel {
            iface_name: Set(val.iface_name.clone()),
            ..Default::default()
        };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for MSSClampServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.clamp_size = Set(self.clamp_size);
        active.update_at = Set(self.update_at);
    }
}
