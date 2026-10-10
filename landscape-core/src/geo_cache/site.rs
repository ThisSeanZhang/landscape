use std::collections::HashSet;

use landscape_common::{
    config_service::geo::{GeoDomainConfig, GeoFileCacheKey, GeoSiteFileConfig},
    database::error::DbError,
    dns::rule::DomainMatchType,
    utils::time::get_f64_timestamp,
};
use regex::Regex;
use sqlx::{QueryBuilder, Sqlite, SqliteConnection, SqlitePool};

use super::{CacheWriteOutcome, db_err};

/// 500 rows x 6 bound columns = 3000 parameters, below SQLite's 32766 limit.
const INSERT_BATCH: usize = 500;

/// Row of a full-content replace; non-Regex `domain` must be pre-normalized
/// (lowercase, no trailing dot), Regex stored verbatim.
#[derive(Debug, Clone)]
pub struct SiteRuleRow {
    pub match_type: DomainMatchType,
    pub domain: String,
    pub attributes: HashSet<String>,
    pub pattern_valid: bool,
}

impl SiteRuleRow {
    /// `pattern_valid` guards the REGEXP arm of the lookup query, which
    /// errors the whole statement on an uncompilable pattern: invalid Regex
    /// rules must simply never match, not break lookups.
    pub fn new(match_type: DomainMatchType, domain: String, attributes: HashSet<String>) -> Self {
        let pattern_valid =
            !matches!(match_type, DomainMatchType::Regex) || Regex::new(&domain).is_ok();
        Self { match_type, domain, attributes, pattern_valid }
    }
}

#[derive(Debug, Clone)]
pub struct SiteRuleHit {
    pub key: GeoFileCacheKey,
    pub match_type: DomainMatchType,
    pub domain: String,
    pub attributes: HashSet<String>,
}

// `DomainMatchType` discriminants align with the dat file encoding.
fn match_type_to_i32(match_type: DomainMatchType) -> i32 {
    match_type as i32
}

fn match_type_from_i32(value: i32) -> Option<DomainMatchType> {
    match value {
        0 => Some(DomainMatchType::Plain),
        1 => Some(DomainMatchType::Regex),
        2 => Some(DomainMatchType::Domain),
        3 => Some(DomainMatchType::Full),
        _ => None,
    }
}

/// Empty sets are NULL, non-empty ones a sorted JSON array.
fn attributes_to_json(attributes: &HashSet<String>) -> Option<String> {
    if attributes.is_empty() {
        return None;
    }
    let mut names: Vec<&str> = attributes.iter().map(String::as_str).collect();
    names.sort_unstable();
    serde_json::to_string(&names).ok()
}

fn attributes_from_json(raw: Option<String>) -> HashSet<String> {
    raw.and_then(|text| serde_json::from_str::<Vec<String>>(&text).ok())
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// `"www.a.b.c"` → `["www.a.b.c", "a.b.c", "b.c", "c"]`.
pub(super) fn suffix_candidates(domain: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut rest = domain;
    loop {
        candidates.push(rest.to_string());
        match rest.find('.') {
            Some(position) => rest = &rest[position + 1..],
            None => break,
        }
    }
    candidates
}

/// Parsed geosite rules cache, one `(name, geo_key)` per entry.
#[derive(Clone)]
pub struct SiteCacheRepository {
    pool: SqlitePool,
}

impl SiteCacheRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Atomically replace every rule of one `(name, geo_key)`. A matching
    /// content hash skips the write entirely.
    pub async fn replace_by_name(
        &self,
        name: &str,
        geo_key: &str,
        content_hash: &str,
        rules: Vec<SiteRuleRow>,
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
            insert_rules(&mut tx, entry_id, &rules).await?;
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
        // PK prefix range delete: rules are clustered by (entry_id, seq)
        sqlx::query("DELETE FROM geo_site_rules WHERE entry_id = ?")
            .bind(entry_id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        insert_rules(&mut tx, entry_id, &rules).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(CacheWriteOutcome::Updated)
    }

    /// Semantic match for one normalized lowercase domain across all
    /// entries: Domain (self or dot-suffix), Full (exact), Plain (substring,
    /// LIKE-escaped), Regex (SQL REGEXP from the sqlx `regexp` feature,
    /// sharing the Rust `regex` engine used by the DNS matcher). Invalid
    /// Regex rows carry `pattern_valid = 0` and never match.
    pub async fn lookup_rules_by_domain(
        &self,
        normalized: &str,
    ) -> Result<Vec<SiteRuleHit>, DbError> {
        let candidates = suffix_candidates(normalized);
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT e.name, e.geo_key, r.match_type, r.domain, r.attributes \
             FROM geo_site_rules AS r JOIN geo_cache_entries AS e ON e.id = r.entry_id \
             WHERE (r.match_type = 2 AND r.domain IN (",
        );
        {
            let mut separated = builder.separated(", ");
            for candidate in &candidates {
                separated.push_bind(candidate.as_str());
            }
        }
        // Plain: subject is the bound query, the pattern escapes the rule
        // column in SQL (`\`, `%`, `_` must be literal under LIKE).
        builder.push(")) OR (r.match_type = 3 AND r.domain = ");
        builder.push_bind(normalized);
        builder.push(") OR (r.match_type = 0 AND ");
        builder.push_bind(normalized);
        builder.push(
            " LIKE '%' || replace(replace(replace(r.domain, '\\', '\\\\'), '%', '\\%'), '_', '\\_') \
             || '%' ESCAPE '\\') OR (r.match_type = 1 AND CASE WHEN r.pattern_valid THEN ",
        );
        // CASE WHEN guarantees pattern_valid is checked before REGEXP:
        // SQLite does not promise AND-term evaluation order, and one
        // uncompilable pattern must not error the whole query.
        builder.push_bind(normalized);
        builder.push(" REGEXP r.domain ELSE 0 END) ORDER BY e.name, e.geo_key, r.seq");

        let rows: Vec<(String, String, i32, String, Option<String>)> =
            builder.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;

        rows.into_iter()
            .map(|(name, key, match_type, domain, attributes)| {
                Some(SiteRuleHit {
                    key: GeoFileCacheKey { name, key },
                    match_type: match_type_from_i32(match_type)?,
                    domain,
                    attributes: attributes_from_json(attributes),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| DbError::Internal("invalid match_type in geo site cache".to_string()))
    }

    /// `content_hash` of one entry, `None` if missing; single-row probe for
    /// drift detection without re-reading rule rows.
    pub async fn load_entry_hash(
        &self,
        name: &str,
        geo_key: &str,
    ) -> Result<Option<String>, DbError> {
        let header: Option<(i64, String)> = sqlx::query_as(
            "SELECT id, content_hash FROM geo_cache_entries WHERE name = ? AND geo_key = ?",
        )
        .bind(name)
        .bind(geo_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(header.map(|(_, content_hash)| content_hash))
    }

    /// [`Self::load_entry`] plus the entry's current `content_hash`.
    pub async fn load_entry_with_hash(
        &self,
        name: &str,
        geo_key: &str,
    ) -> Result<Option<(GeoDomainConfig, String)>, DbError> {
        let header: Option<(i64, String)> = sqlx::query_as(
            "SELECT id, content_hash FROM geo_cache_entries WHERE name = ? AND geo_key = ?",
        )
        .bind(name)
        .bind(geo_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        let Some((entry_id, content_hash)) = header else {
            return Ok(None);
        };

        let rows: Vec<(i32, String, Option<String>)> = sqlx::query_as(
            "SELECT match_type, domain, attributes FROM geo_site_rules \
             WHERE entry_id = ? ORDER BY seq",
        )
        .bind(entry_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        let values = rows
            .into_iter()
            .map(|(match_type, value, attributes)| {
                Some(GeoSiteFileConfig {
                    match_type: match_type_from_i32(match_type)?,
                    value,
                    attributes: attributes_from_json(attributes),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| DbError::Internal("invalid match_type in geo site cache".to_string()))?;

        Ok(Some((
            GeoDomainConfig {
                name: name.to_string(),
                key: geo_key.to_string(),
                values,
            },
            content_hash,
        )))
    }

    /// Full rule list of one entry; entries with zero rules still yield
    /// `Some` with an empty `values`.
    pub async fn load_entry(
        &self,
        name: &str,
        geo_key: &str,
    ) -> Result<Option<GeoDomainConfig>, DbError> {
        Ok(self.load_entry_with_hash(name, geo_key).await?.map(|(config, _)| config))
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

    /// Delete one entry; child rules go through the FK cascade.
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

async fn insert_rules(
    tx: &mut SqliteConnection,
    entry_id: i64,
    rules: &[SiteRuleRow],
) -> Result<(), DbError> {
    for (chunk_index, chunk) in rules.chunks(INSERT_BATCH).enumerate() {
        let base = (chunk_index * INSERT_BATCH) as i64;
        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(
            "INSERT INTO geo_site_rules (entry_id, seq, match_type, domain, attributes, pattern_valid) ",
        );
        builder.push_values(chunk.iter().enumerate(), |mut row, (offset, rule)| {
            row.push_bind(entry_id)
                .push_bind(base + offset as i64)
                .push_bind(match_type_to_i32(rule.match_type.clone()))
                .push_bind(rule.domain.as_str())
                .push_bind(attributes_to_json(&rule.attributes))
                .push_bind(rule.pattern_valid);
        });
        builder.build().execute(&mut *tx).await.map_err(db_err)?;
    }
    Ok(())
}
