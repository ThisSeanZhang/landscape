use crate::repository::{FlowFilterExpr, UpdateActiveModel};
use landscape_common::flow::ip_mark::WanIpRuleConfig;
use migration::SimpleExpr;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type DstIpRuleConfigModel = Model;
pub type DstIpRuleConfigEntity = Entity;
pub type DstIpRuleConfigActiveModel = ActiveModel;
pub type DstIpRuleConfigColumn = Column;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dst_ip_rule_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub index: u32,
    pub enable: bool,
    pub mark: u32,
    #[sea_orm(column_type = "Text")]
    pub source: DBJson,
    pub remark: String,
    pub flow_id: u32,
    pub override_dns: bool,
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

impl From<Model> for WanIpRuleConfig {
    fn from(entity: Model) -> Self {
        WanIpRuleConfig {
            id: entity.id,
            index: entity.index,
            enable: entity.enable,
            mark: entity.mark.into(),
            source: serde_json::from_value(entity.source).unwrap(),
            remark: entity.remark,
            flow_id: entity.flow_id,
            override_dns: entity.override_dns,
            update_at: entity.update_at,
        }
    }
}

impl From<WanIpRuleConfig> for ActiveModel {
    fn from(val: WanIpRuleConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for WanIpRuleConfig {
    fn update(self, active: &mut ActiveModel) {
        active.index = Set(self.index);
        active.enable = Set(self.enable);
        active.mark = Set(self.mark.into());
        active.source = Set(serde_json::to_value(&self.source).unwrap());
        active.remark = Set(self.remark);
        active.flow_id = Set(self.flow_id);
        active.override_dns = Set(self.override_dns);
        active.update_at = Set(self.update_at);
    }
}

impl FlowFilterExpr for DstIpRuleConfigModel {
    fn get_flow_filter(id: landscape_common::config::FlowId) -> SimpleExpr {
        Column::FlowId.eq(id)
    }
}
