use landscape_common::{
    database::{repository::UpdateActiveModel, LandscapeDBFlowFilterExpr},
    flow::config::FlowConfig,
};
use migration::SimpleExpr;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type FlowConfigModel = Model;
pub type FlowConfigEntity = Entity;
pub type FlowConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "flow_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub enable: bool,
    pub flow_id: u32,
    #[sea_orm(column_type = "Json")]
    pub flow_match_rules: DBJson,
    #[sea_orm(column_type = "Json")]
    pub packet_handle_iface_name: DBJson,
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

impl From<Model> for FlowConfig {
    fn from(entity: Model) -> Self {
        FlowConfig {
            id: entity.id,
            enable: entity.enable,
            flow_id: entity.flow_id,
            flow_match_rules: serde_json::from_value(entity.flow_match_rules).unwrap(),
            flow_targets: serde_json::from_value(entity.packet_handle_iface_name).unwrap(),
            remark: entity.remark,
            update_at: entity.update_at,
        }
    }
}

impl Into<ActiveModel> for FlowConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for FlowConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.flow_id = Set(self.flow_id);
        active.flow_match_rules = Set(serde_json::to_value(self.flow_match_rules).unwrap().into());
        active.packet_handle_iface_name =
            Set(serde_json::to_value(self.flow_targets).unwrap().into());
        active.remark = Set(self.remark);
        active.update_at = Set(self.update_at);
    }
}

impl LandscapeDBFlowFilterExpr for FlowConfigModel {
    fn get_flow_filter(id: landscape_common::config::FlowId) -> SimpleExpr {
        Column::FlowId.eq(id)
    }
}
