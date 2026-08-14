use crate::repository::UpdateActiveModel;
use landscape_common::wan_service::firewall::blacklist::FirewallBlacklistConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type FirewallBlacklistConfigModel = Model;
pub type FirewallBlacklistConfigEntity = Entity;
pub type FirewallBlacklistConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "firewall_blacklist_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub enable: bool,
    #[sea_orm(column_type = "Json")]
    pub source: DBJson,
    pub remark: String,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert && self.id.is_not_set() {
            self.id = Set(Uuid::new_v4());
        }
        Ok(self)
    }
}

impl From<Model> for FirewallBlacklistConfig {
    fn from(entity: Model) -> Self {
        FirewallBlacklistConfig {
            id: entity.id,
            enable: entity.enable,
            source: serde_json::from_value(entity.source).unwrap(),
            remark: entity.remark,
            update_at: entity.update_at,
        }
    }
}

impl From<FirewallBlacklistConfig> for ActiveModel {
    fn from(val: FirewallBlacklistConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for FirewallBlacklistConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.source = Set(serde_json::to_value(&self.source).unwrap());
        active.remark = Set(self.remark);
        active.update_at = Set(self.update_at);
    }
}
