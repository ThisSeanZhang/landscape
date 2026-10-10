use std::{path::Path, time::Duration};

use landscape_common::{LANDSCAPE_GEO_CACHE_DIR, database::error::DbError};
use sqlx::{
    Row,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use super::db_err;

/// Bump when the DDL below changes. A version mismatch drops and rebuilds the
/// database; the cache is derivable from the raw sources, no migration needed.
const SITE_CACHE_SCHEMA_VERSION: i64 = 2;
const IP_CACHE_SCHEMA_VERSION: i64 = 1;

const POOL_MAX_CONNECTIONS: u32 = 3;

const ENTRIES_DDL: &str = "
CREATE TABLE IF NOT EXISTS geo_cache_entries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    geo_key      TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    updated_at   REAL NOT NULL,
    UNIQUE (name, geo_key)
);";

const SITE_DDL: &str = "
CREATE TABLE IF NOT EXISTS geo_site_rules (
    entry_id   INTEGER NOT NULL REFERENCES geo_cache_entries(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL,
    match_type INTEGER NOT NULL,
    domain     TEXT NOT NULL,
    attributes TEXT,
    pattern_valid INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (entry_id, seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_site_rules_lookup ON geo_site_rules (match_type, domain);";

const IP_DDL: &str = "
CREATE TABLE IF NOT EXISTS geo_ip_cidrs (
    entry_id      INTEGER NOT NULL REFERENCES geo_cache_entries(id) ON DELETE CASCADE,
    seq           INTEGER NOT NULL,
    family        INTEGER NOT NULL,
    prefix_len    INTEGER NOT NULL,
    network       BLOB NOT NULL,
    reverse_match INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (entry_id, seq)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ip_cidrs_lookup ON geo_ip_cidrs (family, prefix_len, network);";

/// Boot-time open failures can be transient (mount not ready, disk busy), so
/// all of them are retried with a bounded backoff.
const MAX_CONNECT_ATTEMPTS: usize = 5;
const CONNECT_BACKOFF_START: Duration = Duration::from_secs(1);
const CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Openers for the two geo cache databases; runtime-derived data kept
/// deliberately outside the main config database.
pub struct GeoCacheDatabase;

impl GeoCacheDatabase {
    /// `{land_home}/geo/cache/site.sqlite`
    pub async fn open_site(land_home: &Path) -> Result<sqlx::SqlitePool, DbError> {
        Self::open(
            &land_home.join(LANDSCAPE_GEO_CACHE_DIR).join("site.sqlite"),
            SITE_CACHE_SCHEMA_VERSION,
            &[ENTRIES_DDL, SITE_DDL],
        )
        .await
    }

    /// `{land_home}/geo/cache/ip.sqlite`
    pub async fn open_ip(land_home: &Path) -> Result<sqlx::SqlitePool, DbError> {
        Self::open(
            &land_home.join(LANDSCAPE_GEO_CACHE_DIR).join("ip.sqlite"),
            IP_CACHE_SCHEMA_VERSION,
            &[ENTRIES_DDL, IP_DDL],
        )
        .await
    }

    /// Fresh in-memory site cache database (tests and standalone tooling).
    pub async fn site_mem() -> sqlx::SqlitePool {
        Self::mem(SITE_CACHE_SCHEMA_VERSION, &[ENTRIES_DDL, SITE_DDL]).await
    }

    async fn mem(schema_version: i64, ddl: &[&str]) -> sqlx::SqlitePool {
        // every in-memory connection is its own database → one connection
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true)
            .page_size(8192)
            .with_regexp();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("in-memory geo cache db connect failed");
        Self::bootstrap(&pool, schema_version, ddl).await.expect("bootstrap failed");
        pool
    }

    async fn open(
        path: &Path,
        schema_version: i64,
        ddl: &[&str],
    ) -> Result<sqlx::SqlitePool, DbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            // CASCADE deletes in the repositories rely on this
            .foreign_keys(true)
            .page_size(8192)
            // registers the REGEXP function on every pooled connection;
            // the site lookup query depends on it
            .with_regexp();
        let pool = Self::connect_with_retry(options).await?;
        Self::bootstrap(&pool, schema_version, ddl).await?;
        Ok(pool)
    }

    async fn connect_with_retry(
        options: SqliteConnectOptions,
    ) -> Result<sqlx::SqlitePool, DbError> {
        let mut backoff = CONNECT_BACKOFF_START;
        let mut last_err = None;

        for attempt in 1..=MAX_CONNECT_ATTEMPTS {
            match SqlitePoolOptions::new()
                .max_connections(POOL_MAX_CONNECTIONS)
                .connect_with(options.clone())
                .await
            {
                Ok(pool) => return Ok(pool),
                Err(err) => {
                    tracing::error!(
                        "geo cache db connection attempt {}/{} failed: {err:?}",
                        attempt,
                        MAX_CONNECT_ATTEMPTS
                    );
                    last_err = Some(err);
                    if attempt < MAX_CONNECT_ATTEMPTS {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(CONNECT_BACKOFF_MAX);
                    }
                }
            }
        }

        Err(DbError::Internal(format!(
            "geo cache db connect failed: {}",
            last_err.expect("at least one attempt was made")
        )))
    }

    /// Idempotent bootstrap keyed on `PRAGMA user_version`: a mismatch
    /// (including a fresh 0) drops and recreates the cache, a match is a
    /// no-op through `IF NOT EXISTS`.
    async fn bootstrap(
        pool: &sqlx::SqlitePool,
        schema_version: i64,
        ddl: &[&str],
    ) -> Result<(), DbError> {
        let current: i64 = sqlx::query("PRAGMA user_version")
            .fetch_one(pool)
            .await
            .map_err(db_err)?
            .try_get("user_version")
            .map_err(db_err)?;

        let mut tx = pool.begin().await.map_err(db_err)?;

        if current != schema_version {
            // children first: entries cannot drop while rules reference them
            sqlx::raw_sql(
                "DROP TABLE IF EXISTS geo_site_rules; \
                 DROP TABLE IF EXISTS geo_ip_cidrs; \
                 DROP TABLE IF EXISTS geo_cache_entries;",
            )
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }

        for statement in ddl {
            sqlx::raw_sql(statement).execute(&mut *tx).await.map_err(db_err)?;
        }
        sqlx::raw_sql(&format!("PRAGMA user_version = {schema_version}"))
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(())
    }
}

#[cfg(test)]
impl GeoCacheDatabase {
    pub(crate) async fn ip_mem() -> sqlx::SqlitePool {
        Self::mem(IP_CACHE_SCHEMA_VERSION, &[ENTRIES_DDL, IP_DDL]).await
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::GeoCacheDatabase;

    #[tokio::test]
    async fn reopening_with_same_schema_version_keeps_data() {
        let dir = tempdir().unwrap();
        let land_home = dir.path().to_path_buf();

        {
            let pool = GeoCacheDatabase::open_site(&land_home).await.unwrap();
            sqlx::query("INSERT INTO geo_cache_entries (name, geo_key, content_hash, updated_at) VALUES ('geosite', 'CN', 'h1', 0.0)")
                .execute(&pool)
                .await
                .unwrap();
        }

        let pool = GeoCacheDatabase::open_site(&land_home).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM geo_cache_entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn schema_version_mismatch_rebuilds_from_scratch() {
        let dir = tempdir().unwrap();
        let land_home = dir.path().to_path_buf();

        let pool = GeoCacheDatabase::open_ip(&land_home).await.unwrap();
        sqlx::query("INSERT INTO geo_cache_entries (name, geo_key, content_hash, updated_at) VALUES ('geoip', 'US', 'h1', 0.0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 999").execute(&pool).await.unwrap();
        pool.close().await;

        let pool = GeoCacheDatabase::open_ip(&land_home).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM geo_cache_entries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        // tables were recreated, not just emptied
        let version: i64 =
            sqlx::query_scalar("PRAGMA user_version").fetch_one(&pool).await.unwrap();
        assert_eq!(version, 1);
    }
}
