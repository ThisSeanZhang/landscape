use landscape_common::{database::repository::UpdateActiveModel, dns::redirect::DNSRedirectRule};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};
use serde_json;

use crate::{DBId, DBJson, DBTimestamp};

pub type DNSRedirectRuleConfigModel = Model;
pub type DNSRedirectRuleConfigEntity = Entity;
pub type DNSRedirectRuleConfigActiveModel = ActiveModel;
pub type DNSRedirectRuleConfigColumn = Column;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dns_redirect_rule_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    /// 主键 ID
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,

    /// 备注
    #[sea_orm(column_type = "Text", nullable)]
    pub remark: String,

    /// 是否启用
    pub enable: bool,

    /// 匹配规则 JSON
    pub match_rules: DBJson,

    /// 匹配结果 JSON
    pub result_info: DBJson,

    /// 应用的 Flow
    pub apply_flows: DBJson,

    /// 更新时间戳
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

/// 从 Model 转换到 DNSRedirectRule
impl From<Model> for DNSRedirectRule {
    fn from(entity: Model) -> Self {
        DNSRedirectRule {
            id: entity.id,
            remark: entity.remark,
            enable: entity.enable,
            match_rules: serde_json::from_value(entity.match_rules).unwrap(),
            result_info: serde_json::from_value(entity.result_info).unwrap(),
            apply_flows: serde_json::from_value(entity.apply_flows).unwrap(),
            update_at: entity.update_at,
        }
    }
}

/// 从 DNSRedirectRule 转换到 ActiveModel
impl Into<ActiveModel> for DNSRedirectRule {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

/// 更新 ActiveModel 的实现
impl UpdateActiveModel<ActiveModel> for DNSRedirectRule {
    fn update(self, active: &mut ActiveModel) {
        active.remark = Set(self.remark);
        active.enable = Set(self.enable);
        active.match_rules = Set(serde_json::to_value(self.match_rules).unwrap().into());
        active.result_info = Set(serde_json::to_value(self.result_info).unwrap().into());
        active.apply_flows = Set(serde_json::to_value(self.apply_flows).unwrap().into());
        active.update_at = Set(self.update_at);
    }
}
