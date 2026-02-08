use landscape_common::{
    database::{repository::Repository, LandscapeDBTrait, LandscapeServiceDBTrait},
    mac_binding::IpMacBinding,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::DBId;

use super::entity::{Column, IpMacBindingActiveModel, IpMacBindingEntity, IpMacBindingModel};

#[derive(Clone)]
pub struct IpMacBindingRepository {
    db: DatabaseConnection,
}

impl IpMacBindingRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_mac(&self, mac: String) -> Result<Option<IpMacBinding>, String> {
        let model = IpMacBindingEntity::find()
            .filter(Column::Mac.eq(mac))
            .one(self.db())
            .await
            .map_err(|e| e.to_string())?;

        Ok(model.map(|m| m.into()))
    }
}

#[async_trait::async_trait]
impl LandscapeServiceDBTrait for IpMacBindingRepository {}

#[async_trait::async_trait]
impl LandscapeDBTrait for IpMacBindingRepository {}

#[async_trait::async_trait]
impl Repository for IpMacBindingRepository {
    type Model = IpMacBindingModel;
    type Entity = IpMacBindingEntity;
    type ActiveModel = IpMacBindingActiveModel;
    type Data = IpMacBinding;
    type Id = DBId;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
