use landscape_common::dns::redirect::DNSRedirectRule;
use sea_orm::{DatabaseConnection, DbErr, EntityTrait};

use crate::{
    dns_redirect::entity::{
        DNSRedirectRuleConfigActiveModel, DNSRedirectRuleConfigEntity, DNSRedirectRuleConfigModel,
    },
    DBId,
};

#[derive(Clone)]
pub struct DNSRedirectRuleRepository {
    db: DatabaseConnection,
}

impl DNSRedirectRuleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_id(&self, id: DBId) -> Result<Option<DNSRedirectRule>, DbErr> {
        Ok(DNSRedirectRuleConfigEntity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(DNSRedirectRule::from))
    }
}

crate::impl_repository!(
    DNSRedirectRuleRepository,
    DNSRedirectRuleConfigModel,
    DNSRedirectRuleConfigEntity,
    DNSRedirectRuleConfigActiveModel,
    DNSRedirectRule,
    DBId
);

crate::impl_flow_store!(
    DNSRedirectRuleRepository,
    DNSRedirectRuleConfigModel,
    DNSRedirectRuleConfigEntity
);
