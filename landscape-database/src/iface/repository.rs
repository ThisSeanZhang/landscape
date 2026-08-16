use landscape_common::{
    config_service::iface::{IfaceZoneType, NetworkIfaceConfig},
    database::error::DbError,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::iface::entity::Column;

use super::entity::{NetIfaceConfigActiveModel, NetIfaceConfigEntity, NetIfaceConfigModel};

#[derive(Clone)]
pub struct NetIfaceRepository {
    db: DatabaseConnection,
}

impl NetIfaceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn get_all_wan_iface(&self) -> Result<Vec<NetworkIfaceConfig>, DbError> {
        use crate::repository::Repository;
        let result = NetIfaceConfigEntity::find()
            .filter(Column::ZoneType.eq(IfaceZoneType::Wan))
            .all(self.db())
            .await?;

        Ok(result.into_iter().map(From::from).collect())
    }
}

crate::impl_repository!(
    NetIfaceRepository,
    NetIfaceConfigModel,
    NetIfaceConfigEntity,
    NetIfaceConfigActiveModel,
    NetworkIfaceConfig,
    String
);
