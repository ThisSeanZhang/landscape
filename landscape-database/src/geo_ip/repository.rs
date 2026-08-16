use landscape_common::{config_service::geo::GeoIpSourceConfig, database::error::DbError};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

use crate::DBId;

use super::entity::{
    Column, GeoIpSourceConfigActiveModel, GeoIpSourceConfigEntity, GeoIpSourceConfigModel,
};

#[derive(Clone)]
pub struct GeoIpSourceConfigRepository {
    db: DatabaseConnection,
}

impl GeoIpSourceConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn query_by_name(
        &self,
        name: Option<String>,
    ) -> Result<Vec<GeoIpSourceConfig>, DbError> {
        let result = GeoIpSourceConfigEntity::find()
            .filter(Column::Name.contains(name.unwrap_or("".to_string())))
            .order_by_desc(Column::UpdateAt)
            .all(&self.db)
            .await?;
        Ok(result.into_iter().map(From::from).collect())
    }
}

crate::impl_repository!(
    GeoIpSourceConfigRepository,
    GeoIpSourceConfigModel,
    GeoIpSourceConfigEntity,
    GeoIpSourceConfigActiveModel,
    GeoIpSourceConfig,
    DBId
);
