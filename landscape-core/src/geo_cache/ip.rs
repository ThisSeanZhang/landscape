use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use futures_util::TryStreamExt;
use landscape_common::{
    config_service::geo::{GeoFileCacheKey, GeoIpConfig},
    database::error::DbError,
    flow::ip_mark::IpConfig,
    utils::time::get_f64_timestamp,
};
use sqlx::{QueryBuilder, Sqlite, SqliteConnection, SqlitePool, Transaction};
use tokio::sync::mpsc;

use super::{CacheWriteOutcome, db_err};

/// 500 rows x 5 bound columns = 2500 parameters, below SQLite's 32766 limit.
const INSERT_BATCH: usize = 500;

/// Row of a full-content replace; host bits are masked on write.
#[derive(Debug, Clone)]
pub struct IpCidrRow {
    pub network: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone)]
pub struct IpCidrHit {
    pub key: GeoFileCacheKey,
    pub network: IpAddr,
    pub prefix_len: u8,
}

/// Events used to stream one `(name, geo_key)` replacement without holding a
/// full CIDR list in memory. `Begin` opens the per-key transaction, `Cidrs`
/// append bounded batches, and `End` commits it. Dropping the sender before
/// `End` rolls the transaction back.
#[derive(Debug)]
pub enum IpCacheStreamEvent {
    Begin { key: String, content_hash: String },
    Cidrs(Vec<IpCidrRow>),
    End,
}

/// Big-endian network bytes (4/16) with host bits masked to zero.
pub fn masked_network_bytes(network: IpAddr, prefix_len: u8) -> Vec<u8> {
    match network {
        IpAddr::V4(addr) => {
            let prefix_len = prefix_len.min(32) as u32;
            let mask = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len) };
            (u32::from(addr) & mask).to_be_bytes().to_vec()
        }
        IpAddr::V6(addr) => {
            let prefix_len = prefix_len.min(128) as u32;
            let mask = if prefix_len == 0 { 0 } else { u128::MAX << (128 - prefix_len) };
            (u128::from(addr) & mask).to_be_bytes().to_vec()
        }
    }
}

fn network_from_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))),
        _ => None,
    }
}

/// One `(family, prefix_len, masked network)` probe per prefix length
/// (33 v4 / 129 v6); collect-all semantics, callers decide precedence.
fn prefix_probes(ip: IpAddr) -> Vec<(i32, i32, Vec<u8>)> {
    match ip {
        IpAddr::V4(addr) => {
            let bits = u32::from(addr);
            (0..=32)
                .map(|prefix_len| {
                    let mask = if prefix_len == 0 { 0 } else { u32::MAX << (32 - prefix_len) };
                    (4, prefix_len, (bits & mask).to_be_bytes().to_vec())
                })
                .collect()
        }
        IpAddr::V6(addr) => {
            let bits = u128::from(addr);
            (0..=128)
                .map(|prefix_len| {
                    let mask = if prefix_len == 0 { 0 } else { u128::MAX << (128 - prefix_len) };
                    (6, prefix_len, (bits & mask).to_be_bytes().to_vec())
                })
                .collect()
        }
    }
}

fn family_of(ip: IpAddr) -> i32 {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}

/// Parsed geoip CIDR cache, one `(name, geo_key)` per entry.
#[derive(Clone)]
pub struct IpCacheRepository {
    pool: SqlitePool,
}

impl IpCacheRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Atomically replace every CIDR of one `(name, geo_key)`. A matching
    /// content hash skips the write entirely.
    pub async fn replace_by_name(
        &self,
        name: &str,
        geo_key: &str,
        content_hash: &str,
        cidrs: Vec<IpCidrRow>,
    ) -> Result<CacheWriteOutcome, DbError> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        let existing: Option<(i64, String)> = sqlx::query_as(
            "SELECT id, content_hash FROM geo_cache_entries WHERE name = ? AND geo_key = ?",
        )
        .bind(name)
        .bind(geo_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;

        let Some((entry_id, old_hash)) = existing else {
            let entry_id: i64 = sqlx::query_scalar(
                "INSERT INTO geo_cache_entries (name, geo_key, content_hash, updated_at) \
                 VALUES (?, ?, ?, ?) RETURNING id",
            )
            .bind(name)
            .bind(geo_key)
            .bind(content_hash)
            .bind(get_f64_timestamp())
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            insert_cidrs(&mut tx, entry_id, &cidrs).await?;
            tx.commit().await.map_err(db_err)?;
            return Ok(CacheWriteOutcome::Inserted);
        };

        if old_hash == content_hash {
            tx.commit().await.map_err(db_err)?;
            return Ok(CacheWriteOutcome::Unchanged);
        }

        sqlx::query("UPDATE geo_cache_entries SET content_hash = ?, updated_at = ? WHERE id = ?")
            .bind(content_hash)
            .bind(get_f64_timestamp())
            .bind(entry_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("DELETE FROM geo_ip_cidrs WHERE entry_id = ?")
            .bind(entry_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        insert_cidrs(&mut tx, entry_id, &cidrs).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(CacheWriteOutcome::Updated)
    }

    /// Stream a sequence of per-key replacements. Each `Begin`/`Cidrs`/`End`
    /// group is committed independently, matching `replace_by_name` semantics.
    pub async fn replace_stream(
        &self,
        name: &str,
        mut rx: mpsc::Receiver<IpCacheStreamEvent>,
    ) -> Result<HashMap<String, CacheWriteOutcome>, DbError> {
        let mut outcomes = HashMap::new();
        let mut current: Option<StreamWrite> = None;

        while let Some(event) = rx.recv().await {
            match event {
                IpCacheStreamEvent::Begin { key, content_hash } => {
                    if current.is_some() {
                        return Err(DbError::Internal(
                            "geo ip cache stream received Begin before End".to_string(),
                        ));
                    }
                    current = Some(
                        begin_stream_entry(self, name, key.to_ascii_uppercase(), content_hash)
                            .await?,
                    );
                }
                IpCacheStreamEvent::Cidrs(cidrs) => {
                    let Some(current) = current.as_mut() else {
                        return Err(DbError::Internal(
                            "geo ip cache stream received Cidrs before Begin".to_string(),
                        ));
                    };
                    if let Some((tx, entry_id, next_seq)) = current.write_state_mut() {
                        insert_cidr_chunk(tx, entry_id, *next_seq, &cidrs).await?;
                        *next_seq = next_seq.checked_add(cidrs.len() as i64).ok_or_else(|| {
                            DbError::Internal("geo ip cache sequence overflow".to_string())
                        })?;
                    }
                }
                IpCacheStreamEvent::End => {
                    let Some(current) = current.take() else {
                        return Err(DbError::Internal(
                            "geo ip cache stream received End before Begin".to_string(),
                        ));
                    };
                    let (key, outcome) = current.finish().await?;
                    outcomes.insert(key, outcome);
                }
            }
        }

        if current.is_some() {
            return Err(DbError::Internal("geo ip cache stream closed before End".to_string()));
        }
        Ok(outcomes)
    }

    /// Content hashes for every cached key under one source name.
    pub async fn entry_hashes_for_name(
        &self,
        name: &str,
    ) -> Result<HashMap<String, String>, DbError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT geo_key, content_hash FROM geo_cache_entries WHERE name = ?")
                .bind(name)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(rows.into_iter().collect())
    }

    /// Every `(name, geo_key)` whose CIDR list contains `ip`, matching prefix
    /// included; all probes batched into one round trip.
    pub async fn lookup_ip(&self, ip: IpAddr) -> Result<Vec<IpCidrHit>, DbError> {
        let probes = prefix_probes(ip);

        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT e.name, e.geo_key, c.prefix_len, c.network \
             FROM geo_ip_cidrs AS c JOIN geo_cache_entries AS e ON e.id = c.entry_id \
             WHERE (c.family, c.prefix_len, c.network) IN (",
        );
        {
            // push_values would emit a VALUES keyword, invalid inside an IN list
            let mut first = true;
            for (family, prefix_len, network) in probes.iter() {
                if !first {
                    builder.push(", ");
                }
                first = false;
                builder
                    .push("(")
                    .push_bind(*family)
                    .push(", ")
                    .push_bind(*prefix_len)
                    .push(", ")
                    .push_bind(network.as_slice())
                    .push(")");
            }
            builder.push(")");
        }
        let rows: Vec<(String, String, i32, Vec<u8>)> = builder
            .push(" ORDER BY e.name, e.geo_key, c.seq")
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;

        rows.into_iter()
            .map(|(name, key, prefix_len, network)| {
                Some(IpCidrHit {
                    key: GeoFileCacheKey { name, key },
                    network: network_from_bytes(&network)?,
                    prefix_len: prefix_len as u8,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| DbError::Internal("invalid network blob in geo ip cache".to_string()))
    }

    /// Full CIDR list of one entry.
    pub async fn load_entry(
        &self,
        name: &str,
        geo_key: &str,
    ) -> Result<Option<GeoIpConfig>, DbError> {
        let mut values = Vec::new();
        if !self.extend_cidrs(name, geo_key, &mut values, |config| config).await? {
            return Ok(None);
        }
        Ok(Some(GeoIpConfig {
            name: name.to_string(),
            key: geo_key.to_string(),
            values,
        }))
    }

    /// Stream one entry's CIDRs directly into `output`, optionally mapping
    /// each row into the caller's runtime representation. The entry's row
    /// count is used to reserve output capacity up front, and the raw SQL row
    /// list is never materialized in full.
    pub async fn extend_cidrs<T, F>(
        &self,
        name: &str,
        geo_key: &str,
        output: &mut Vec<T>,
        mut map: F,
    ) -> Result<bool, DbError>
    where
        F: FnMut(IpConfig) -> T,
    {
        let header: Option<(i64, i64)> = sqlx::query_as(
            "SELECT e.id, \
                    (SELECT COUNT(*) FROM geo_ip_cidrs AS c WHERE c.entry_id = e.id) \
             FROM geo_cache_entries AS e WHERE e.name = ? AND e.geo_key = ?",
        )
        .bind(name)
        .bind(geo_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some((entry_id, count)) = header else {
            return Ok(false);
        };
        let count = usize::try_from(count)
            .map_err(|_| DbError::Internal("geo ip entry is too large".to_string()))?;
        output.reserve(count);

        let mut rows = sqlx::query_as::<_, (i32, Vec<u8>)>(
            "SELECT prefix_len, network FROM geo_ip_cidrs WHERE entry_id = ? ORDER BY seq",
        )
        .bind(entry_id)
        .fetch(&self.pool);
        while let Some((prefix_len, network)) = rows.try_next().await.map_err(db_err)? {
            let ip = network_from_bytes(&network).ok_or_else(|| {
                DbError::Internal("invalid network blob in geo ip cache".to_string())
            })?;
            output.push(map(IpConfig { ip, prefix: prefix_len as u32 }));
        }
        Ok(true)
    }

    pub async fn keys_for_name(&self, name: &str) -> Result<Vec<GeoFileCacheKey>, DbError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT name, geo_key FROM geo_cache_entries WHERE name = ?")
                .bind(name)
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(rows.into_iter().map(|(name, key)| GeoFileCacheKey { name, key }).collect())
    }

    pub async fn list_keys(&self) -> Result<Vec<GeoFileCacheKey>, DbError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT name, geo_key FROM geo_cache_entries")
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(rows.into_iter().map(|(name, key)| GeoFileCacheKey { name, key }).collect())
    }

    pub async fn has_name(&self, name: &str) -> Result<bool, DbError> {
        let found: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM geo_cache_entries WHERE name = ? LIMIT 1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(found.is_some())
    }

    pub async fn delete_by_name(&self, name: &str, geo_key: &str) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM geo_cache_entries WHERE name = ? AND geo_key = ?")
            .bind(name)
            .bind(geo_key)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}

struct StreamWrite {
    key: String,
    inserted: bool,
    state: StreamWriteState,
}

enum StreamWriteState {
    Unchanged,
    Writing { tx: Transaction<'static, Sqlite>, entry_id: i64, next_seq: i64 },
}

impl StreamWrite {
    fn write_state_mut(&mut self) -> Option<(&mut SqliteConnection, i64, &mut i64)> {
        match &mut self.state {
            StreamWriteState::Unchanged => None,
            StreamWriteState::Writing { tx, entry_id, next_seq } => {
                Some((&mut **tx, *entry_id, next_seq))
            }
        }
    }

    async fn finish(self) -> Result<(String, CacheWriteOutcome), DbError> {
        match self.state {
            StreamWriteState::Unchanged => Ok((self.key, CacheWriteOutcome::Unchanged)),
            StreamWriteState::Writing { tx, .. } => {
                tx.commit().await.map_err(db_err)?;
                let outcome = if self.inserted {
                    CacheWriteOutcome::Inserted
                } else {
                    CacheWriteOutcome::Updated
                };
                Ok((self.key, outcome))
            }
        }
    }
}

async fn begin_stream_entry(
    repo: &IpCacheRepository,
    name: &str,
    key: String,
    content_hash: String,
) -> Result<StreamWrite, DbError> {
    let mut tx = repo.pool.begin().await.map_err(db_err)?;
    let existing: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, content_hash FROM geo_cache_entries WHERE name = ? AND geo_key = ?",
    )
    .bind(name)
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;

    let Some((entry_id, old_hash)) = existing else {
        sqlx::query(
            "INSERT INTO geo_cache_entries (name, geo_key, content_hash, updated_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(name)
        .bind(&key)
        .bind(&content_hash)
        .bind(get_f64_timestamp())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        let entry_id: i64 =
            sqlx::query_scalar("SELECT id FROM geo_cache_entries WHERE name = ? AND geo_key = ?")
                .bind(name)
                .bind(&key)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
        return Ok(StreamWrite {
            key,
            inserted: true,
            state: StreamWriteState::Writing { tx, entry_id, next_seq: 0 },
        });
    };

    if old_hash == content_hash {
        return Ok(StreamWrite {
            key,
            inserted: false,
            state: StreamWriteState::Unchanged,
        });
    }

    sqlx::query("UPDATE geo_cache_entries SET content_hash = ?, updated_at = ? WHERE id = ?")
        .bind(&content_hash)
        .bind(get_f64_timestamp())
        .bind(entry_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query("DELETE FROM geo_ip_cidrs WHERE entry_id = ?")
        .bind(entry_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    Ok(StreamWrite {
        key,
        inserted: false,
        state: StreamWriteState::Writing { tx, entry_id, next_seq: 0 },
    })
}

async fn insert_cidrs(
    tx: &mut SqliteConnection,
    entry_id: i64,
    cidrs: &[IpCidrRow],
) -> Result<(), DbError> {
    insert_cidr_chunk(tx, entry_id, 0, cidrs).await
}

async fn insert_cidr_chunk(
    tx: &mut SqliteConnection,
    entry_id: i64,
    seq_base: i64,
    cidrs: &[IpCidrRow],
) -> Result<(), DbError> {
    for (chunk_index, chunk) in cidrs.chunks(INSERT_BATCH).enumerate() {
        let base = seq_base + (chunk_index * INSERT_BATCH) as i64;
        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(
            "INSERT INTO geo_ip_cidrs (entry_id, seq, family, prefix_len, network) ",
        );
        builder.push_values(chunk.iter().enumerate(), |mut row, (offset, cidr)| {
            row.push_bind(entry_id)
                .push_bind(base + offset as i64)
                .push_bind(family_of(cidr.network))
                .push_bind(cidr.prefix_len as i32)
                .push_bind(masked_network_bytes(cidr.network, cidr.prefix_len));
        });
        builder.build().execute(&mut *tx).await.map_err(db_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use tokio::sync::mpsc;

    use super::{
        IpCacheRepository, IpCacheStreamEvent, IpCidrRow, masked_network_bytes, prefix_probes,
    };
    use crate::geo_cache::{CacheWriteOutcome, GeoCacheDatabase};

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn cidr(network: &str, prefix_len: u8) -> IpCidrRow {
        IpCidrRow { network: ip(network), prefix_len }
    }

    async fn repo() -> IpCacheRepository {
        IpCacheRepository::new(GeoCacheDatabase::ip_mem().await)
    }

    #[test]
    fn masking_clears_host_bits() {
        assert_eq!(masked_network_bytes(ip("10.1.2.3"), 8), vec![10, 0, 0, 0]);
        assert_eq!(masked_network_bytes(ip("10.1.2.3"), 32), vec![10, 1, 2, 3]);
        assert_eq!(masked_network_bytes(ip("10.1.2.3"), 0), vec![0, 0, 0, 0]);
        assert_eq!(
            masked_network_bytes(ip("2001:db8::1"), 32),
            vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn probes_cover_every_prefix_length() {
        assert_eq!(prefix_probes(ip("1.2.3.4")).len(), 33);
        assert_eq!(prefix_probes(ip("::1")).len(), 129);
        assert_eq!(prefix_probes(ip("1.2.3.4"))[32], (4, 32, vec![1, 2, 3, 4]));
    }

    #[tokio::test]
    async fn replace_reports_inserted_unchanged_updated() {
        let repo = repo().await;
        assert_eq!(
            repo.replace_by_name("geoip", "CN", "hash-1", vec![cidr("10.0.0.0", 8)]).await.unwrap(),
            CacheWriteOutcome::Inserted
        );
        assert_eq!(
            repo.replace_by_name("geoip", "CN", "hash-1", vec![cidr("10.0.0.0", 8)]).await.unwrap(),
            CacheWriteOutcome::Unchanged
        );
        assert_eq!(
            repo.replace_by_name("geoip", "CN", "hash-2", vec![cidr("192.168.0.0", 16)])
                .await
                .unwrap(),
            CacheWriteOutcome::Updated
        );

        let entry = repo.load_entry("geoip", "CN").await.unwrap().unwrap();
        assert_eq!(entry.values.len(), 1);
        assert_eq!(entry.values[0].ip, ip("192.168.0.0"));
        assert_eq!(entry.values[0].prefix, 16);
    }

    #[tokio::test]
    async fn lookup_ip_collects_hits_across_keys_and_masks_host_bits() {
        let repo = repo().await;
        repo.replace_by_name(
            "geoip",
            "CN",
            "hash-1",
            vec![cidr("10.0.0.0", 8), cidr("2001:db8::", 32)],
        )
        .await
        .unwrap();
        repo.replace_by_name("other", "PRIVATE", "hash-1", vec![cidr("10.9.9.9", 8)])
            .await
            .unwrap();

        let hits = repo.lookup_ip(ip("10.1.2.3")).await.unwrap();
        assert_eq!(hits.len(), 2);
        let mut keys: Vec<(String, String)> =
            hits.iter().map(|hit| (hit.key.name.clone(), hit.key.key.clone())).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                ("geoip".to_string(), "CN".to_string()),
                ("other".to_string(), "PRIVATE".to_string())
            ]
        );
        assert!(hits.iter().all(|hit| hit.prefix_len == 8));

        let hits = repo.lookup_ip(ip("2001:db8::5")).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].network, ip("2001:db8::"));

        assert!(repo.lookup_ip(ip("11.0.0.1")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn zero_prefix_matches_everything() {
        let repo = repo().await;
        repo.replace_by_name("geoip", "ALL", "hash-1", vec![cidr("0.0.0.0", 0)]).await.unwrap();
        assert_eq!(repo.lookup_ip(ip("203.0.113.9")).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn extend_cidrs_maps_rows_without_load_entry_vec() {
        let repo = repo().await;
        repo.replace_by_name(
            "geoip",
            "CN",
            "hash",
            vec![cidr("10.0.0.0", 8), cidr("2001:db8::", 32)],
        )
        .await
        .unwrap();

        let mut output = Vec::new();
        let found = repo
            .extend_cidrs("geoip", "CN", &mut output, |config| {
                (config.ip.to_string(), config.prefix)
            })
            .await
            .unwrap();
        assert!(found);
        assert_eq!(output, vec![("10.0.0.0".to_string(), 8), ("2001:db8::".to_string(), 32)]);

        let mut empty = Vec::new();
        assert!(!repo.extend_cidrs("geoip", "MISSING", &mut empty, |config| config).await.unwrap());
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn replace_stream_commits_batched_cidrs_and_skips_unchanged() {
        let repo = repo().await;
        let (tx, rx) = mpsc::channel(8);
        tx.send(IpCacheStreamEvent::Begin {
            key: "cn".to_string(),
            content_hash: "hash-stream-1".to_string(),
        })
        .await
        .unwrap();
        tx.send(IpCacheStreamEvent::Cidrs(vec![cidr("10.0.0.0", 8)])).await.unwrap();
        tx.send(IpCacheStreamEvent::Cidrs(vec![cidr("2001:db8::", 32)])).await.unwrap();
        tx.send(IpCacheStreamEvent::End).await.unwrap();
        drop(tx);

        let outcomes = repo.replace_stream("geoip", rx).await.unwrap();
        assert_eq!(outcomes.get("CN"), Some(&CacheWriteOutcome::Inserted));
        let entry = repo.load_entry("geoip", "CN").await.unwrap().unwrap();
        assert_eq!(entry.values.len(), 2);
        assert_eq!(entry.values[0].ip, ip("10.0.0.0"));
        assert_eq!(entry.values[1].prefix, 32);
        assert_eq!(
            repo.entry_hashes_for_name("geoip").await.unwrap().get("CN").map(String::as_str),
            Some("hash-stream-1")
        );

        let (tx, rx) = mpsc::channel(8);
        tx.send(IpCacheStreamEvent::Begin {
            key: "CN".to_string(),
            content_hash: "hash-stream-1".to_string(),
        })
        .await
        .unwrap();
        tx.send(IpCacheStreamEvent::Cidrs(vec![cidr("192.0.2.0", 24)])).await.unwrap();
        tx.send(IpCacheStreamEvent::End).await.unwrap();
        drop(tx);

        let outcomes = repo.replace_stream("geoip", rx).await.unwrap();
        assert_eq!(outcomes.get("CN"), Some(&CacheWriteOutcome::Unchanged));
        let entry = repo.load_entry("geoip", "CN").await.unwrap().unwrap();
        assert_eq!(entry.values.len(), 2);
        assert_eq!(entry.values[0].ip, ip("10.0.0.0"));
    }

    #[tokio::test]
    async fn replace_stream_rolls_back_when_sender_drops_before_end() {
        let repo = repo().await;
        repo.replace_by_name("geoip", "CN", "old-hash", vec![cidr("10.0.0.0", 8)]).await.unwrap();

        let (tx, rx) = mpsc::channel(8);
        tx.send(IpCacheStreamEvent::Begin {
            key: "CN".to_string(),
            content_hash: "new-hash".to_string(),
        })
        .await
        .unwrap();
        tx.send(IpCacheStreamEvent::Cidrs(vec![cidr("192.0.2.0", 24)])).await.unwrap();
        drop(tx);

        assert!(repo.replace_stream("geoip", rx).await.is_err());
        let entry = repo.load_entry("geoip", "CN").await.unwrap().unwrap();
        assert_eq!(entry.values.len(), 1);
        assert_eq!(entry.values[0].ip, ip("10.0.0.0"));
        assert_eq!(
            repo.entry_hashes_for_name("geoip").await.unwrap().get("CN").map(String::as_str),
            Some("old-hash")
        );
    }
}

#[cfg(test)]
mod mem_probe {
    use std::net::{IpAddr, Ipv4Addr};

    use landscape_common::flow::{ip_mark::IpConfig, mark::FlowMark, runtime::IpMarkInfo};
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    use super::{IpCacheRepository, IpCacheStreamEvent, IpCidrRow};
    use crate::geo_cache::GeoCacheDatabase;

    fn memory_report(stage: &str) {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
        let mut fields = statm.split_whitespace();
        let _virtual_pages: u64 = fields.next().unwrap().parse().unwrap();
        let rss_pages: u64 = fields.next().unwrap().parse().unwrap();
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let mall = unsafe { libc::mallinfo2() };
        eprintln!(
            "{stage}: rss={} KiB malloc_in_use={} KiB malloc_free_held={} KiB",
            rss_pages * page_size / 1024,
            mall.uordblks as u64 / 1024,
            mall.fordblks as u64 / 1024,
        );
    }

    /// Reproduce the transient RSS/high-water spike caused by loading one
    /// large IP cache entry and then cloning it into a runtime rule set.
    ///
    /// ```text
    /// GEO_MEM_PROBE_CIDRS=2000000 cargo test -p landscape-core --release \
    ///   --lib memory_probe_load_large_ip_entry -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "manual allocator high-water probe"]
    async fn memory_probe_load_large_ip_entry() {
        let total: usize = std::env::var("GEO_MEM_PROBE_CIDRS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000);
        let dir = tempdir().unwrap();
        let repo = IpCacheRepository::new(
            GeoCacheDatabase::open_ip(&dir.path().join("cache")).await.unwrap(),
        );
        let (tx, rx) = mpsc::channel(8);
        let producer = tokio::spawn(async move {
            tx.send(IpCacheStreamEvent::Begin {
                key: "CN".to_string(),
                content_hash: "hash".to_string(),
            })
            .await
            .unwrap();
            let mut index = 0usize;
            while index < total {
                let end = (index + 500).min(total);
                let batch = (index..end)
                    .map(|value| IpCidrRow {
                        network: IpAddr::V4(Ipv4Addr::from(value as u32)),
                        prefix_len: 32,
                    })
                    .collect::<Vec<_>>();
                tx.send(IpCacheStreamEvent::Cidrs(batch)).await.unwrap();
                index = end;
            }
            tx.send(IpCacheStreamEvent::End).await.unwrap();
        });
        repo.replace_stream("geoip", rx).await.unwrap();
        producer.await.unwrap();
        unsafe { libc::malloc_trim(0) };
        memory_report("before load_entry");

        let entry = repo.load_entry("geoip", "CN").await.unwrap().unwrap();
        assert_eq!(entry.values.len(), total);
        memory_report("after load_entry");
        assert_eq!(entry.values[0], IpConfig { ip: "0.0.0.0".parse().unwrap(), prefix: 32 });
        drop(entry);
        unsafe { libc::malloc_trim(0) };
        memory_report("after load_entry drop+trim");

        let mut marks = Vec::new();
        repo.extend_cidrs("geoip", "CN", &mut marks, |cidr| IpMarkInfo {
            mark: FlowMark::default(),
            cidr,
            priority: 0,
        })
        .await
        .unwrap();
        marks.sort_unstable_by_key(|info| (info.cidr.ip, info.cidr.prefix, info.priority));
        marks.dedup_by(|left, right| left.cidr == right.cidr);
        memory_report("after streamed runtime conversion");
        assert_eq!(marks.len(), total);
        drop(marks);
        unsafe { libc::malloc_trim(0) };
        memory_report("after conversion drop+trim");
    }
}
