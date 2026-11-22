//! Geo runtime cache in two standalone SQLite databases (`geo/cache/site.sqlite`
//! and `ip.sqlite`). Content is fully derivable from raw or snapshot sources,
//! so schema changes drop and rebuild instead of migrating.

mod db;
mod ip;
mod matcher;
mod registry;
mod site;

#[cfg(test)]
mod tests;

pub use db::GeoCacheDatabase;
pub use ip::{IpCacheRepository, IpCacheStreamEvent, IpCidrHit, IpCidrRow};
pub use matcher::DomainMatcher;
pub use registry::{GeoMatcherCacheKey, SiteMatcherRegistry};
pub use site::{SiteCacheRepository, SiteCacheStreamEvent, SiteRuleHit, SiteRuleRow};

use landscape_common::{
    config_service::geo::{GeoFileCacheKey, QueryGeoKey},
    database::error::DbError,
};
use sqlx::{QueryBuilder, Sqlite, SqlitePool};

async fn search_keys(
    pool: &SqlitePool,
    filter: &QueryGeoKey,
) -> Result<Vec<GeoFileCacheKey>, DbError> {
    let mut sql =
        QueryBuilder::<Sqlite>::new("SELECT name, geo_key FROM geo_cache_entries WHERE 1=1");
    if let Some(name) = &filter.name {
        sql.push(" AND name = ").push_bind(name);
    }
    if let Some(key) = filter.key.as_deref().filter(|key| !key.is_empty()) {
        sql.push(" AND instr(geo_key, ").push_bind(key.to_ascii_uppercase()).push(") > 0");
    }
    if let Some(q) = filter.q.as_deref().map(str::trim).filter(|q| !q.is_empty()) {
        let q = q.to_ascii_uppercase();
        sql.push(" AND instr(upper(name) || '/' || geo_key, ").push_bind(q.clone()).push(") > 0");
        sql.push(" ORDER BY CASE WHEN geo_key = ")
            .push_bind(q.clone())
            .push(" THEN 0 WHEN instr(geo_key, ")
            .push_bind(q)
            .push(") = 1 THEN 1 ELSE 2 END, geo_key, name");
    } else {
        sql.push(" ORDER BY geo_key, name");
    }
    if let Some(limit) = filter.limit {
        sql.push(" LIMIT ").push_bind(i64::from(limit));
    }
    let rows = sql.build_query_as::<(String, String)>().fetch_all(pool).await.map_err(db_err)?;
    Ok(rows.into_iter().map(|(name, key)| GeoFileCacheKey { name, key }).collect())
}

/// Result of a full-content replace for one `(name, geo_key)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheWriteOutcome {
    Inserted,
    Updated,
    /// Content hash matched; the write was skipped.
    Unchanged,
}

pub(crate) fn db_err(error: sqlx::Error) -> DbError {
    DbError::Internal(format!("geo cache db error: {error}"))
}
