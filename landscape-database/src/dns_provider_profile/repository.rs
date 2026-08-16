use landscape_common::database::error::DbError;
use landscape_common::dns::provider_profile::DnsProviderProfile;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use super::entity::{
    Column, DnsProviderProfileActiveModel, DnsProviderProfileEntity, DnsProviderProfileModel,
};
use crate::repository::Repository;
use crate::DBId;

#[derive(Clone)]
pub struct DnsProviderProfileRepository {
    db: DatabaseConnection,
}

impl DnsProviderProfileRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<DnsProviderProfile>, DbError> {
        let model =
            DnsProviderProfileEntity::find().filter(Column::Name.eq(name)).one(self.db()).await?;
        Ok(model.map(Into::into))
    }
}

crate::impl_repository!(
    DnsProviderProfileRepository,
    DnsProviderProfileModel,
    DnsProviderProfileEntity,
    DnsProviderProfileActiveModel,
    DnsProviderProfile,
    DBId
);
