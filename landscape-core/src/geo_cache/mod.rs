//! Geo runtime cache in two standalone SQLite databases (`geo/cache/site.sqlite`
//! and `ip.sqlite`). Content is fully derivable from the raw sources, so schema
//! changes drop and rebuild instead of migrating.

mod db;
mod ip;
mod site;

pub use db::GeoCacheDatabase;
pub use ip::{IpCacheRepository, IpCidrHit, IpCidrRow};
pub use site::{SiteCacheRepository, SiteRuleHit, SiteRuleRow};

use landscape_common::database::error::DbError;

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
