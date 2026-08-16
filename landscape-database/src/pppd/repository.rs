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
