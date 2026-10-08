use landscape_common::database::store::ConfigStore;
use landscape_common::flow::ip_mark::WanIpRuleConfig;
use sea_orm::DatabaseConnection;

use super::entity::{DstIpRuleConfigActiveModel, DstIpRuleConfigEntity, DstIpRuleConfigModel};
use crate::DBId;

#[derive(Clone)]
pub struct DstIpRuleRepository {
    db: DatabaseConnection,
}

impl DstIpRuleRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    DstIpRuleRepository,
    DstIpRuleConfigModel,
    DstIpRuleConfigEntity,
    DstIpRuleConfigActiveModel,
    WanIpRuleConfig,
    DBId
);

crate::impl_flow_store!(DstIpRuleRepository, DstIpRuleConfigModel, DstIpRuleConfigEntity);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<WanIpRuleConfig>
    for DstIpRuleRepository
{
    async fn check_zone(
        &self,
        _config: &WanIpRuleConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }

    async fn validate_cross(
        &self,
        config: &mut WanIpRuleConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        if let Some(existing) = self
            .find_by_id(config.id)
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
            && existing.flow_id != config.flow_id
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "flow_id of dst-ip rule '{}' cannot be changed after creation",
                    config.id
                ),
            });
        }
        Ok(())
    }
}
