use landscape_common::database::error::DbError;
use landscape_common::ddns::DdnsJob;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use super::entity::{Column, DdnsJobActiveModel, DdnsJobEntity, DdnsJobModel};
use crate::repository::Repository;
use crate::DBId;

#[derive(Clone)]
pub struct DdnsJobRepository {
    db: DatabaseConnection,
}

impl DdnsJobRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_enabled(&self) -> Result<Vec<DdnsJob>, DbError> {
        let models = DdnsJobEntity::find().filter(Column::Enable.eq(true)).all(self.db()).await?;
        Ok(models.into_iter().map(Into::into).collect())
    }
}

crate::impl_repository!(
    DdnsJobRepository,
    DdnsJobModel,
    DdnsJobEntity,
    DdnsJobActiveModel,
    DdnsJob,
    DBId
);
