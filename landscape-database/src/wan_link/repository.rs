use landscape_common::database::error::DbError;
use landscape_common::database::LandscapeStore;
use landscape_common::wan_service::link::WanLinkConfig;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use super::entity::{Column, WanLinkActiveModel, WanLinkEntity, WanLinkModel};
use crate::repository::Repository;
use crate::DBId;

#[derive(Clone)]
pub struct WanLinkRepository {
    db: DatabaseConnection,
}

impl WanLinkRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_attach_iface_name(
        &self,
        attach_iface_name: &str,
    ) -> Result<Vec<WanLinkConfig>, DbError> {
        let models = WanLinkEntity::find()
            .filter(Column::AttachIfaceName.eq(attach_iface_name))
            .all(self.db())
            .await?;
        Ok(models.into_iter().map(Into::into).collect())
    }

    /// All links whose runtime net iface is the given one (attach iface for
    /// ethernet / native PPPoE, the ppp device for pppd links).
    pub async fn find_links_touching_iface(
        &self,
        net_iface: &str,
    ) -> Result<Vec<WanLinkConfig>, DbError> {
        // The wan_links table is tiny; filter in memory instead of relying
        // on a LIKE over a JSON column (whitespace- and wildcard-sensitive).
        Ok(self
            .list()
            .await?
            .into_iter()
            .filter(|link| link.net_iface_name() == net_iface)
            .collect())
    }
}

crate::impl_repository!(
    WanLinkRepository,
    WanLinkModel,
    WanLinkEntity,
    WanLinkActiveModel,
    WanLinkConfig,
    DBId
);
