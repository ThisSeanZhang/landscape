use crate::repository::UpdateActiveModel;
use landscape_common::config::gateway::HttpUpstreamRuleConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type GatewayHttpUpstreamModel = Model;
pub type GatewayHttpUpstreamEntity = Entity;
pub type GatewayHttpUpstreamActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "gateway_http_upstream_rules")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub enable: bool,
    pub match_rule: DBJson,
    pub upstream: DBJson,
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

impl From<Model> for HttpUpstreamRuleConfig {
    fn from(entity: Model) -> Self {
        HttpUpstreamRuleConfig {
            id: entity.id,
            name: entity.name,
            enable: entity.enable,
            match_rule: serde_json::from_value(entity.match_rule).unwrap(),
            upstream: serde_json::from_value(entity.upstream).unwrap(),
            update_at: entity.update_at,
        }
    }
}

impl Into<ActiveModel> for HttpUpstreamRuleConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for HttpUpstreamRuleConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.enable = Set(self.enable);
        active.match_rule = Set(serde_json::to_value(&self.match_rule).unwrap());
        active.upstream = Set(serde_json::to_value(&self.upstream).unwrap());
        active.update_at = Set(self.update_at);
    }
}
