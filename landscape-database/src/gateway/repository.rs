use landscape_common::database::error::DbError;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};

use super::entity::{
    GatewayHttpUpstreamActiveModel, GatewayHttpUpstreamEntity, GatewayHttpUpstreamModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct GatewayHttpUpstreamRepository {
    db: DatabaseConnection,
}

impl GatewayHttpUpstreamRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn list_checked(&self) -> Result<Vec<HttpUpstreamRuleConfig>, GatewayError> {
        GatewayHttpUpstreamEntity::find()
            .all(&self.db)
            .await
            .map_err(DbError::from)?
            .into_iter()
            .map(GatewayHttpUpstreamModel::into_config_checked)
            .collect()
    }

    pub async fn find_by_id_checked(
        &self,
        id: DBId,
    ) -> Result<Option<HttpUpstreamRuleConfig>, GatewayError> {
        GatewayHttpUpstreamEntity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(DbError::from)?
            .map(GatewayHttpUpstreamModel::into_config_checked)
            .transpose()
    }

    pub async fn count(&self) -> Result<u64, GatewayError> {
        Ok(GatewayHttpUpstreamEntity::find().count(&self.db).await.map_err(DbError::from)?)
    }

    /// Remove a malformed row without deserializing its old JSON payload.
    /// Only initialization recovery uses this path; live changes preflight all rules.
    pub async fn delete_by_id_raw(&self, id: DBId) -> Result<(), GatewayError> {
        GatewayHttpUpstreamEntity::delete_by_id(id).exec(&self.db).await.map_err(DbError::from)?;
        Ok(())
    }
}

crate::impl_repository!(
    GatewayHttpUpstreamRepository,
    GatewayHttpUpstreamModel,
    GatewayHttpUpstreamEntity,
    GatewayHttpUpstreamActiveModel,
    HttpUpstreamRuleConfig,
    DBId
);

crate::impl_trivial_validator!(GatewayHttpUpstreamRepository, HttpUpstreamRuleConfig);
