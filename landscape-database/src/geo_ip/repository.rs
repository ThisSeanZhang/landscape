use landscape_common::{
    config_service::geo::{GeoIpSource, GeoIpSourceConfig},
    database::{error::DbError, store::ConfigStore},
    utils::time::{MILL_A_DAY, get_f64_timestamp},
};
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

    /// Task-only schedule write-back; UPDATE-only, `Ok(false)` when the row
    /// was deleted mid-task.
    pub async fn bump_refresh_schedule(&self, id: DBId) -> Result<bool, DbError> {
        let Some(mut config) = self.find_by_id(id).await? else {
            return Ok(false);
        };
        if let GeoIpSource::Url { next_update_at, .. } = &mut config.source {
            *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
        }
        match self.checked_upsert(config).await {
            Ok(_) | Err(DbError::Conflict) => Ok(true),
            Err(e) => Err(e),
        }
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

crate::impl_trivial_validator!(GeoIpSourceConfigRepository, GeoIpSourceConfig);

#[cfg(test)]
mod tests {
    use landscape_common::{
        config_service::geo::{GeoIpFileFormat, GeoIpSource, GeoIpSourceConfig},
        database::store::ConfigStore,
    };
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn url_config(name: &str) -> GeoIpSourceConfig {
        GeoIpSourceConfig {
            id: Uuid::new_v4(),
            update_at: 0.0,
            name: name.to_string(),
            enable: true,
            source: GeoIpSource::Url {
                url: format!("https://example.com/{name}.dat"),
                next_update_at: 0.0,
                format: GeoIpFileFormat::Dat,
                txt_key: None,
            },
        }
    }

    #[tokio::test]
    async fn bump_refresh_schedule_advances_next_update_at() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = provider.geo_ip_rule_store();
        let saved = store.upsert(url_config("geoip")).await.unwrap().new;

        assert!(store.bump_refresh_schedule(saved.id).await.unwrap());

        let updated = store.find_by_id(saved.id).await.unwrap().unwrap();
        let GeoIpSource::Url { next_update_at, .. } = updated.source else {
            panic!("source must stay url");
        };
        assert!(next_update_at > 0.0);
    }

    #[tokio::test]
    async fn bump_refresh_schedule_does_not_resurrect_deleted_config() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = provider.geo_ip_rule_store();
        let saved = store.upsert(url_config("geoip")).await.unwrap().new;

        store.delete_and_get(saved.id).await.unwrap();

        assert!(!store.bump_refresh_schedule(saved.id).await.unwrap());
        assert!(store.find_by_id(saved.id).await.unwrap().is_none());
    }
}
