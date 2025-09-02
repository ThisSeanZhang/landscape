use landscape_common::{
    database::{repository::Repository, LandscapeDBTrait, LandscapeFlowTrait},
    dns::redirect::DNSRedirectRule,
    // error::LdError,
};
// use migration::LockType;
use sea_orm::{
    DatabaseConnection,
    DbErr,
    EntityTrait,
    // ActiveModelTrait, ColumnTrait,  IntoActiveModel,
    // QueryFilter, QuerySelect, TransactionTrait,
};

use crate::{
    dns_redirect::entity::{
        // DNSRedirectRuleConfigColumn,
        DNSRedirectRuleConfigActiveModel,
        DNSRedirectRuleConfigEntity,
        DNSRedirectRuleConfigModel,
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
            .map(|model| DNSRedirectRule::from(model)))
    }
}

#[async_trait::async_trait]
impl LandscapeDBTrait for DNSRedirectRuleRepository {}

#[async_trait::async_trait]
impl LandscapeFlowTrait for DNSRedirectRuleRepository {}

#[async_trait::async_trait]
impl Repository for DNSRedirectRuleRepository {
    type Model = DNSRedirectRuleConfigModel;
    type Entity = DNSRedirectRuleConfigEntity;
    type ActiveModel = DNSRedirectRuleConfigActiveModel;
    type Data = DNSRedirectRule;
    type Id = DBId;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
