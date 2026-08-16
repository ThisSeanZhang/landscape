use landscape_common::database::error::DbError;
use landscape_common::metric::connect::ConnectGlobalStats;

use super::hot_sqlite;
use super::store::DuckMetricStore;

impl DuckMetricStore {
    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        if force_refresh {
            hot_sqlite::rebuild_global_stats_cache(&self.hot_pool).await.map_err(|error| {
                landscape_common::database::error::DbError::Internal(format!(
                    "failed to rebuild connect global stats cache: {}",
                    error
                ))
            })
        } else {
            hot_sqlite::query_global_stats(&self.hot_pool).await.map_err(|error| {
                landscape_common::database::error::DbError::Internal(format!(
                    "failed to query connect global stats cache: {}",
                    error
                ))
            })
        }
    }
}
