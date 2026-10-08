use crate::repository::UpdateActiveModel;
use landscape_common::wan_link::WanLinkConfig;
use sea_orm::{ActiveValue::Set, entity::prelude::*};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type WanLinkConfigModel = Model;
pub type WanLinkConfigEntity = Entity;
pub type WanLinkConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "wan_links")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub attach_iface_name: String,
    pub kind: DBJson,
    pub v4: DBJson,
    pub pd: DBJson,
    pub nat: DBJson,
    pub firewall: DBJson,
    pub mss: DBJson,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for WanLinkConfig {
    fn from(entity: Model) -> Self {
        WanLinkConfig {
            id: entity.id,
            name: entity.name,
            attach_iface_name: entity.attach_iface_name,
            kind: serde_json::from_value(entity.kind).unwrap(),
            v4: serde_json::from_value(entity.v4).unwrap(),
            pd: serde_json::from_value(entity.pd).unwrap(),
            nat: serde_json::from_value(entity.nat).unwrap(),
            firewall: serde_json::from_value(entity.firewall).unwrap(),
            mss: serde_json::from_value(entity.mss).unwrap(),
            update_at: entity.update_at,
        }
    }
}

impl From<WanLinkConfig> for ActiveModel {
    fn from(val: WanLinkConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for WanLinkConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.attach_iface_name = Set(self.attach_iface_name);
        active.kind = Set(serde_json::to_value(&self.kind).unwrap());
        active.v4 = Set(serde_json::to_value(&self.v4).unwrap());
        active.pd = Set(serde_json::to_value(&self.pd).unwrap());
        active.nat = Set(serde_json::to_value(&self.nat).unwrap());
        active.firewall = Set(serde_json::to_value(&self.firewall).unwrap());
        active.mss = Set(serde_json::to_value(&self.mss).unwrap());
        active.update_at = Set(self.update_at);
    }
}
