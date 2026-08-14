use crate::repository::UpdateActiveModel;
use landscape_common::sys_service::gateway::{HttpUpstreamMatchRule, HttpUpstreamRuleConfig};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};
use serde_json::json;

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
        serde_json::from_value(json!({
            "id": entity.id,
            "name": entity.name,
            "enable": entity.enable,
            "match_rule": entity.match_rule,
            "upstream": entity.upstream,
            "update_at": entity.update_at,
        }))
        .unwrap()
    }
}

impl From<HttpUpstreamRuleConfig> for ActiveModel {
    fn from(val: HttpUpstreamRuleConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for HttpUpstreamRuleConfig {
    fn update(self, active: &mut ActiveModel) {
        let match_rule = match &self.match_rule {
            HttpUpstreamMatchRule::Host { path_groups } => {
                json!({ "t": "host", "domains": self.domains, "path_groups": path_groups })
            }
            HttpUpstreamMatchRule::SniProxy => {
                json!({ "t": "sni_proxy", "domains": self.domains })
            }
            HttpUpstreamMatchRule::LegacyPathPrefix { prefix } => {
                json!({ "t": "path_prefix", "domains": self.domains, "prefix": prefix })
            }
        };

        active.name = Set(self.name);
        active.enable = Set(self.enable);
        active.match_rule = Set(match_rule);
        active.upstream = Set(serde_json::to_value(&self.upstream).unwrap());
        active.update_at = Set(self.update_at);
    }
}
