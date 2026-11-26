use crate::repository::UpdateActiveModel;
use landscape_common::sys_service::gateway::{
    GatewayError, HttpUpstreamConfig, HttpUpstreamMatchRule, HttpUpstreamRuleConfig,
};
use sea_orm::{ActiveValue::Set, entity::prelude::*};
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

impl Model {
    /// Decode using the rule's compatibility format, without panicking on a
    /// malformed JSON column or exposing configured header values in errors.
    pub fn into_config_checked(self) -> Result<HttpUpstreamRuleConfig, GatewayError> {
        let id = self.id;
        let upstream = self.upstream.clone();
        serde_json::from_value(json!({
            "id": self.id,
            "name": self.name,
            "enable": self.enable,
            "match_rule": self.match_rule,
            "upstream": self.upstream,
            "update_at": self.update_at,
        }))
        .map_err(|_| {
            let field = if serde_json::from_value::<HttpUpstreamConfig>(upstream).is_err() {
                "upstream"
            } else {
                "match_rule"
            };
            GatewayError::InvalidStoredRule {
                id,
                reason: format!("invalid '{field}' configuration"),
            }
        })
    }
}

impl From<Model> for HttpUpstreamRuleConfig {
    fn from(entity: Model) -> Self {
        // Generic writers retain their infallible repository contract. Gateway
        // service reads use the checked decoder before attempting a mutation.
        entity.into_config_checked().expect("invalid persisted gateway rule")
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
