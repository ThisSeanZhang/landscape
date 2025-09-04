use landscape_common::{
    config::dns::DNSRuleConfig,
    database::{repository::UpdateActiveModel, LandscapeDBFlowFilterExpr},
};
use migration::SimpleExpr;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type DNSRuleConfigModel = Model;
pub type DNSRuleConfigEntity = Entity;
pub type DNSRuleConfigActiveModel = ActiveModel;
pub type DNSRuleConfigColumn = Column;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dns_rule_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    /// 主键 ID
    pub id: DBId,
    pub index: u32,
    pub name: String,
    pub enable: bool,
    pub filter: DBJson,
    pub resolve_mode: DBJson,
    pub upstream_id: DBId,
    pub mark: u32,
    /// 虽然是 JSON 但是考虑到可能存储较多信息
    #[sea_orm(column_type = "Text")]
    pub source: String,
    pub flow_id: u32,
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

impl From<Model> for DNSRuleConfig {
    fn from(entity: Model) -> Self {
        DNSRuleConfig {
            id: entity.id,
            name: entity.name,
            index: entity.index,
            enable: entity.enable,
            filter: serde_json::from_value(entity.filter).unwrap(),
            resolve_mode: serde_json::from_value(entity.resolve_mode).unwrap(),
            upstream_id: entity.upstream_id,
            mark: entity.mark.into(),
            source: serde_json::from_str(&entity.source).unwrap(),
            flow_id: entity.flow_id,
            update_at: entity.update_at,
        }
    }
}

impl Into<ActiveModel> for DNSRuleConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for DNSRuleConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.index = Set(self.index);
        active.enable = Set(self.enable);
        active.filter = Set(serde_json::to_value(self.filter).unwrap().into());
        active.resolve_mode = Set(serde_json::to_value(self.resolve_mode).unwrap().into());
        active.upstream_id = Set(self.upstream_id);
        active.mark = Set(self.mark.into());
        active.source = Set(serde_json::to_string(&self.source).unwrap());
        active.flow_id = Set(self.flow_id);
        active.update_at = Set(self.update_at);
    }
}

impl LandscapeDBFlowFilterExpr for DNSRuleConfigModel {
    fn get_flow_filter(id: landscape_common::config::FlowId) -> SimpleExpr {
        Column::FlowId.eq(id)
    }
}
