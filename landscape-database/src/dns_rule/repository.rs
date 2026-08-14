use landscape_common::dns::rule::DNSRuleConfig;
use sea_orm::{DatabaseConnection, DbErr, EntityTrait};

use crate::{
    dns_rule::entity::{DNSRuleConfigActiveModel, DNSRuleConfigEntity, DNSRuleConfigModel},
    DBId,
};

#[derive(Clone)]
pub struct DNSRuleRepository {
    db: DatabaseConnection,
}

impl DNSRuleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_id(&self, id: DBId) -> Result<Option<DNSRuleConfig>, DbErr> {
        Ok(DNSRuleConfigEntity::find_by_id(id).one(&self.db).await?.map(DNSRuleConfig::from))
    }
}

crate::impl_repository!(
    DNSRuleRepository,
    DNSRuleConfigModel,
    DNSRuleConfigEntity,
    DNSRuleConfigActiveModel,
    DNSRuleConfig,
    DBId
);

crate::impl_flow_store!(DNSRuleRepository, DNSRuleConfigModel, DNSRuleConfigEntity);
