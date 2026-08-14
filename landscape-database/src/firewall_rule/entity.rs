use crate::repository::UpdateActiveModel;
use landscape_common::wan_service::firewall::FirewallRuleConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type FirewallRuleConfigModel = Model;
pub type FirewallRuleConfigEntity = Entity;
pub type FirewallRuleConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "firewall_rule_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    /// 主键 ID
    pub id: DBId,
    pub index: u32,
    pub enable: bool,
    pub remark: String,
    #[sea_orm(column_type = "Json")]
    pub items: DBJson,
    pub mark: u32,
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

impl From<Model> for FirewallRuleConfig {
    fn from(entity: Model) -> Self {
        FirewallRuleConfig {
            id: entity.id,
            index: entity.index,
            enable: entity.enable,
            remark: entity.remark,
            items: serde_json::from_value(entity.items).unwrap(),
            mark: entity.mark.into(),
            update_at: entity.update_at,
        }
    }
}

impl From<FirewallRuleConfig> for ActiveModel {
    fn from(val: FirewallRuleConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for FirewallRuleConfig {
    fn update(self, active: &mut ActiveModel) {
        active.index = Set(self.index);
        active.enable = Set(self.enable);
        active.remark = Set(self.remark);
        active.items = Set(serde_json::to_value(self.items).unwrap());
        active.mark = Set(self.mark.into());
        active.update_at = Set(self.update_at);
    }
}
