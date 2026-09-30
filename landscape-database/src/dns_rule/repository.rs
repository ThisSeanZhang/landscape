use landscape_common::dns::rule::DNSRuleConfig;
use sea_orm::{DatabaseConnection, DbErr, EntityTrait};

use crate::{
    DBId,
    dns_rule::entity::{DNSRuleConfigActiveModel, DNSRuleConfigEntity, DNSRuleConfigModel},
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

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<DNSRuleConfig> for DNSRuleRepository {
    async fn check_zone(
        &self,
        _config: &DNSRuleConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }

    async fn validate_cross(
        &self,
        config: &DNSRuleConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        if let Some(existing) = self
            .find_by_id(config.id)
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
            && existing.flow_id != config.flow_id
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "flow_id of DNS rule '{}' cannot be changed after creation",
                    config.id
                ),
            });
        }
        Ok(())
    }
}
