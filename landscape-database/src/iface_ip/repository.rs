use landscape_common::wan_service::ip_config::IfaceIpServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    IfaceIpServiceConfigActiveModel, IfaceIpServiceConfigEntity, IfaceIpServiceConfigModel,
};

#[derive(Clone)]
pub struct IfaceIpServiceRepository {
    db: DatabaseConnection,
}

impl IfaceIpServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    IfaceIpServiceRepository,
    IfaceIpServiceConfigModel,
    IfaceIpServiceConfigEntity,
    IfaceIpServiceConfigActiveModel,
    IfaceIpServiceConfig,
    String
);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<IfaceIpServiceConfig>
    for IfaceIpServiceRepository
{
    async fn check_zone(
        &self,
        config: &IfaceIpServiceConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        crate::validator::ZoneChecker::new(self.db.clone()).check(config).await
    }

    async fn validate_cross(
        &self,
        config: &IfaceIpServiceConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        use landscape_common::wan_service::ip_config::IfaceIpModelConfig;

        if config.enable && matches!(&config.ip_model, IfaceIpModelConfig::PPPoE { .. }) {
            let attached_pppds =
                crate::pppd::repository::PPPDServiceRepository::new(self.db.clone())
                    .get_pppd_configs_by_attach_iface_name(config.iface_name.clone())
                    .await
                    .map_err(landscape_common::service::ServiceConfigError::internal)?;
            if !attached_pppds.is_empty() {
                return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "Interface '{}' already has PPPD-based PPPoE configured; remove it before enabling native PPPoE",
                        config.iface_name
                    ),
                });
            }
        }
        Ok(())
    }
}
