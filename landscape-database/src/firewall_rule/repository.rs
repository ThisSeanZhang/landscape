use landscape_common::wan_service::firewall::FirewallRuleConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    FirewallRuleConfigActiveModel, FirewallRuleConfigEntity, FirewallRuleConfigModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct FirewallRuleRepository {
    db: DatabaseConnection,
}

impl FirewallRuleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    FirewallRuleRepository,
    FirewallRuleConfigModel,
    FirewallRuleConfigEntity,
    FirewallRuleConfigActiveModel,
    FirewallRuleConfig,
    DBId
);

crate::impl_trivial_validator!(FirewallRuleRepository, FirewallRuleConfig);
