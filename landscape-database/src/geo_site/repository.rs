use landscape_common::{
    config_service::geo::{GeoSiteSource, GeoSiteSourceConfig, normalize_adguard_key},
    database::{error::DbError, store::ConfigStore},
    utils::time::{MILL_A_DAY, get_f64_timestamp},
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder};

use crate::DBId;

use super::entity::{Column, GeoSiteConfigActiveModel, GeoSiteConfigEntity, GeoSiteConfigModel};

#[derive(Clone)]
pub struct GeoSiteConfigRepository {
    db: DatabaseConnection,
}

impl GeoSiteConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn query_by_name(
        &self,
        name: Option<String>,
    ) -> Result<Vec<GeoSiteSourceConfig>, DbError> {
        let result = GeoSiteConfigEntity::find()
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
        match &mut config.source {
            GeoSiteSource::Url { next_update_at, .. }
            | GeoSiteSource::AdguardHome { next_update_at, .. } => {
                *next_update_at = get_f64_timestamp() + MILL_A_DAY as f64;
            }
            GeoSiteSource::Direct { .. } => return Ok(true),
        }
        if let GeoSiteSource::AdguardHome { key, .. } = &mut config.source {
            *key = normalize_adguard_key(key);
        }
        match self.checked_upsert(config).await {
            Ok(_) | Err(DbError::Conflict) => Ok(true),
            Err(e) => Err(e),
        }
    }
}

crate::impl_repository!(
    GeoSiteConfigRepository,
    GeoSiteConfigModel,
    GeoSiteConfigEntity,
    GeoSiteConfigActiveModel,
    GeoSiteSourceConfig,
    DBId
);

crate::impl_trivial_validator!(GeoSiteConfigRepository, GeoSiteSourceConfig);

#[cfg(test)]
mod tests {
    use landscape_common::{
        config_service::geo::{GeoSiteSource, GeoSiteSourceConfig},
        database::store::ConfigStore,
    };
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn adguard_config(name: &str) -> GeoSiteSourceConfig {
        GeoSiteSourceConfig {
            id: Uuid::new_v4(),
            update_at: 0.0,
            name: name.to_string(),
            enable: true,
            source: GeoSiteSource::AdguardHome {
                url: format!("https://example.com/{name}.txt"),
                next_update_at: 0.0,
                key: " adguard ".to_string(),
            },
        }
    }

    #[tokio::test]
    async fn bump_refresh_schedule_advances_schedule_and_normalizes_key() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = provider.geo_site_rule_store();
        let saved = store.upsert(adguard_config("ads")).await.unwrap().new;

        assert!(store.bump_refresh_schedule(saved.id).await.unwrap());

        let updated = store.find_by_id(saved.id).await.unwrap().unwrap();
        let GeoSiteSource::AdguardHome { next_update_at, key, .. } = updated.source else {
            panic!("source must stay adguard_home");
        };
        assert!(next_update_at > 0.0);
        assert_eq!(key, "ADGUARD");
    }

    #[tokio::test]
    async fn bump_refresh_schedule_does_not_resurrect_deleted_config() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = provider.geo_site_rule_store();
        let saved = store.upsert(adguard_config("ads")).await.unwrap().new;

        store.delete_and_get(saved.id).await.unwrap();

        assert!(!store.bump_refresh_schedule(saved.id).await.unwrap());
        assert!(store.find_by_id(saved.id).await.unwrap().is_none());
    }
}
