use landscape_common::database::store::ConfigStore;
use landscape_common::{database::error::DbError, wan_service::pppd::PPPDServiceConfig};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use super::entity::{
    Column, PPPDServiceConfigActiveModel, PPPDServiceConfigEntity, PPPDServiceConfigModel,
};

#[derive(Clone)]
pub struct PPPDServiceRepository {
    db: DatabaseConnection,
}

impl PPPDServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_pppd_configs_by_attach_iface_name(
        &self,
        attach_name: String,
    ) -> Result<Vec<PPPDServiceConfig>, DbError> {
        use crate::repository::Repository;
        let all = PPPDServiceConfigEntity::find()
            .filter(Column::AttachIfaceName.eq(attach_name))
            .all(self.db())
            .await?;
        Ok(all.into_iter().map(PPPDServiceConfig::from).collect())
    }
}

crate::impl_repository!(
    PPPDServiceRepository,
    PPPDServiceConfigModel,
    PPPDServiceConfigEntity,
    PPPDServiceConfigActiveModel,
    PPPDServiceConfig,
    String
);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<PPPDServiceConfig>
    for PPPDServiceRepository
{
    async fn check_zone(
        &self,
        config: &PPPDServiceConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        crate::validator::ZoneChecker::new(self.db.clone()).check(config).await
    }

    async fn validate_cross(
        &self,
        config: &PPPDServiceConfig,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        use landscape_common::wan_service::ip_config::IfaceIpModelConfig;

        if self
            .find_by_id(config.attach_iface_name.clone())
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?
            .is_some()
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "PPPoE attach interface '{}' cannot be an existing PPP interface",
                    config.attach_iface_name
                ),
            });
        }

        let existing_pppd = self
            .find_by_id(config.iface_name.clone())
            .await
            .map_err(landscape_common::service::ServiceConfigError::internal)?;
        let managed_iface_exists =
            crate::iface::repository::NetIfaceRepository::new(self.db.clone())
                .find_by_id(config.iface_name.clone())
                .await
                .map_err(landscape_common::service::ServiceConfigError::internal)?
                .is_some();
        if existing_pppd.is_none() && managed_iface_exists {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "PPPoE interface '{}' conflicts with an existing interface",
                    config.iface_name
                ),
            });
        }

        if config.enable
            && let Some(ip_config) =
                crate::iface_ip::repository::IfaceIpServiceRepository::new(self.db.clone())
                    .find_by_id(config.attach_iface_name.clone())
                    .await
                    .map_err(landscape_common::service::ServiceConfigError::internal)?
            && ip_config.enable
            && matches!(ip_config.ip_model, IfaceIpModelConfig::PPPoE { .. })
        {
            return Err(landscape_common::service::ServiceConfigError::InvalidConfig {
                reason: format!(
                    "Interface '{}' already uses native PPPoE in IP Config; disable it before enabling PPPD-based PPPoE",
                    config.attach_iface_name
                ),
            });
        }
        Ok(())
    }
}
