use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;

use landscape_common::database::error::DbError;
use landscape_common::database::repository::LandscapeDBStore;
use landscape_common::database::store::Change;
use sea_orm::error::RuntimeErr;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction,
    DbErr, EntityTrait, FromQueryResult, IdenStatic, IntoActiveModel, Iterable, PrimaryKeyToColumn,
    QueryFilter, TransactionTrait,
};

use crate::repository::UpdateActiveModel;

type IdTypeOf<E> = <<E as EntityTrait>::PrimaryKey as sea_orm::PrimaryKeyTrait>::ValueType;

/// Runs `$body(txn)` inside a transaction, retrying retryable SQLite write races
/// (see [`is_retryable_code`]) with bounded jitter. Retries cover every statement
/// in the transaction and the COMMIT itself, because WAL read-to-write upgrades
/// can hit SQLITE_BUSY / SQLITE_BUSY_SNAPSHOT at any point; a failed attempt is
/// rolled back and re-run in a fresh transaction (re-reading the latest snapshot).
///
/// A macro because the body borrows the transaction for the duration of its
/// future, which a `FnMut`-generic signature cannot express without GATs.
/// `$body` takes `&DatabaseTransaction` and returns `Result<T, UpsertErr>`.
macro_rules! txn_retry_loop {
    ($self:expr, $body:expr) => {{
        let mut retries = 0u32;
        loop {
            let txn = $self.db.begin().await?;
            let result = $body(&txn).await;
            match result {
                Ok(value) => match txn.commit().await {
                    Ok(()) => return Ok(value),
                    Err(err) if is_retryable_db_error(&err) => {
                        // A failed COMMIT terminates the transaction; nothing to roll back.
                        retries += 1;
                        if retries >= MAX_RETRIES {
                            return Err(upsert_retry_exhausted(
                                retryable_code(&err).unwrap_or_default(),
                            ));
                        }
                        tokio::time::sleep(retry_delay(retries)).await;
                    }
                    Err(err) => return Err(err.into()),
                },
                Err(UpsertErr::Conflict) => {
                    rollback_txn(txn).await;
                    return Err(DbError::Conflict);
                }
                Err(UpsertErr::Retry(code)) => {
                    rollback_txn(txn).await;
                    retries += 1;
                    if retries >= MAX_RETRIES {
                        return Err(upsert_retry_exhausted(code));
                    }
                    tokio::time::sleep(retry_delay(retries)).await;
                }
                Err(UpsertErr::Database(e)) => {
                    rollback_txn(txn).await;
                    return Err(e);
                }
            }
        }
    }};
}

/// Max attempts for a retryable write race. In WAL mode a losing transaction can
/// fail immediately (busy_timeout does not cover read-to-write upgrades); each
/// attempt re-reads the latest snapshot, and the jitter breaks lock-step retry
/// loops between concurrent writers.
const MAX_RETRIES: u32 = 5;

/// Bounded random sleep (1-8ms plus a per-retry ramp) before retrying a write
/// race. Entropy mixes a global counter with the wall clock so two racing
/// writers can never reproduce each other's retry rhythm.
fn retry_delay(retries: u32) -> std::time::Duration {
    static RETRY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = RETRY_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is before UNIX_EPOCH")
        .subsec_nanos();
    // splitmix64-style mixing: spreads the sequential counter over the jitter range
    let entropy = (ns as u64) ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let jitter_ms = 1 + (entropy % 8);
    std::time::Duration::from_millis(jitter_ms + (retries as u64) * 3)
}

/// Outcome of one `upsert_inner` attempt.
enum UpsertErr {
    /// Optimistic-lock mismatch: stored `update_at` differs from the incoming one.
    Conflict,
    /// Retryable transient failure: another transaction committed the same
    /// primary key after our snapshot (SQLITE_CONSTRAINT_PRIMARYKEY), or the
    /// write hit a WAL lock/snapshot race (SQLITE_BUSY / SQLITE_BUSY_SNAPSHOT).
    /// The caller must roll back and retry the whole batch in a fresh transaction.
    /// Carries the sqlite result code for diagnostics.
    Retry(String),
    /// Fatal database error.
    Database(DbError),
}

impl From<DbErr> for UpsertErr {
    fn from(err: DbErr) -> Self {
        // Classify at conversion time so no `?` site can bypass the retry loop:
        // any statement inside the transaction can hit a retryable SQLite race.
        if is_retryable_db_error(&err) {
            UpsertErr::Retry(retryable_code(&err).unwrap_or_default())
        } else {
            UpsertErr::Database(err.into())
        }
    }
}

/// Generic writer: folds "read old value + validate + write" into a single
/// transaction. Every write reads `old` in the same snapshot as the write,
/// refreshes `update_at` server-side; batch writes are all-or-nothing.
///
/// SQLite-only: retry classification and WAL semantics assume the SQLite
/// backend (see `is_retryable_code`). Postgres would need its own handling
/// (serialization failures etc.).
pub struct StoreWriter<E, D> {
    db: DatabaseConnection,
    _marker: PhantomData<(E, D)>,
}

impl<E, D> StoreWriter<E, D> {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db, _marker: PhantomData }
    }
}

impl<E, D> StoreWriter<E, D>
where
    E: EntityTrait,
    E::Model: Into<D> + FromQueryResult + IntoActiveModel<E::ActiveModel> + Clone + Send,
    E::ActiveModel: ActiveModelTrait<Entity = E> + ActiveModelBehavior + Send,
    D: Into<E::ActiveModel>
        + From<E::Model>
        + UpdateActiveModel<E::ActiveModel>
        + LandscapeDBStore<IdTypeOf<E>>
        + Clone
        + Send
        + Sync
        + Debug,
    IdTypeOf<E>: Clone + Eq + std::hash::Hash + Send + Sync,
    sea_orm::Value: From<IdTypeOf<E>>,
{
    /// Blind upsert; `update_at` is refreshed to now.
    pub async fn upsert(&self, config: D) -> Result<Change<D>, DbError> {
        txn_retry_loop!(self, |txn| self.upsert_inner(txn, config.clone(), false))
    }

    /// Optimistic-lock write: stored `update_at` must match the incoming one, otherwise `DbError::Conflict`.
    pub async fn checked_upsert(&self, config: D) -> Result<Change<D>, DbError> {
        txn_retry_loop!(self, |txn| self.upsert_inner(txn, config.clone(), true))
    }

    /// Batch blind upsert; all succeed or all roll back in a single transaction.
    pub async fn upsert_many(&self, configs: Vec<D>) -> Result<Vec<Change<D>>, DbError> {
        txn_retry_loop!(self, |txn| self.upsert_many_inner(txn, &configs, false))
    }

    /// Batch optimistic-lock write; all succeed or all roll back in a single transaction.
    pub async fn checked_upsert_many(&self, configs: Vec<D>) -> Result<Vec<Change<D>>, DbError> {
        txn_retry_loop!(self, |txn| self.upsert_many_inner(txn, &configs, true))
    }

    /// Read and delete within a transaction, returning the deleted value.
    pub async fn delete_and_get(&self, id: IdTypeOf<E>) -> Result<Option<D>, DbError> {
        let id_ref = &id;
        txn_retry_loop!(self, |txn| async move {
            let model = <E as EntityTrait>::find_by_id(id_ref.clone()).one(txn).await?;
            if let Some(model) = model {
                <E as EntityTrait>::delete_by_id(id_ref.clone()).exec(txn).await?;
                Ok::<_, UpsertErr>(Some(model.into()))
            } else {
                Ok(None)
            }
        })
    }

    /// Batch read by id with a single `IN` query; preserves input order and
    /// duplicates, silently skips missing ids.
    pub async fn find_ids(&self, ids: Vec<IdTypeOf<E>>) -> Result<Vec<D>, DbError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let pk =
            <E as EntityTrait>::PrimaryKey::iter().next().expect("entity must have a primary key");
        let pk_column = <E as EntityTrait>::PrimaryKey::into_column(pk);

        let models =
            <E as EntityTrait>::find().filter(pk_column.is_in(ids.clone())).all(&self.db).await?;

        let mut by_id: HashMap<IdTypeOf<E>, D> = HashMap::with_capacity(models.len());
        for model in models {
            let d: D = model.into();
            by_id.insert(d.get_id(), d);
        }

        Ok(ids.into_iter().filter_map(|id| by_id.get(&id).cloned()).collect())
    }

    /// Runs each upsert in `configs` inside one transaction; retry semantics
    /// are those of `txn_retry_loop!`.
    async fn upsert_many_inner(
        &self,
        txn: &DatabaseTransaction,
        configs: &[D],
        checked: bool,
    ) -> Result<Vec<Change<D>>, UpsertErr> {
        let mut changes = Vec::with_capacity(configs.len());
        for config in configs {
            changes.push(self.upsert_inner(txn, config.clone(), checked).await?);
        }
        Ok(changes)
    }

    async fn upsert_inner(
        &self,
        txn: &DatabaseTransaction,
        mut config: D,
        checked: bool,
    ) -> Result<Change<D>, UpsertErr> {
        let old_model = <E as EntityTrait>::find_by_id(config.get_id()).one(txn).await?;
        let old: Option<D> = old_model.as_ref().map(|model| model.clone().into());

        // Client-echoed version, used only for the optimistic-lock comparison.
        let incoming_ts = config.get_update_at();

        // The new version must be strictly increasing from the stored one
        // (`next_update_at`), and never derived from the client's `incoming_ts`,
        // which could be far in the future and poison every later bump.
        // A pure insert has no previous version, so the server clock defines it.
        let now = landscape_common::utils::time::get_f64_timestamp();
        let new_ts = match &old {
            Some(old) => old.next_update_at(now),
            None => now,
        };
        config.set_update_at(new_ts);

        if let Some(model) = old_model {
            if checked {
                // Atomic optimistic lock: the conditional UPDATE (WHERE update_at =
                // incoming_ts) closes the read-then-write race; a concurrent
                // committed write makes it affect zero rows → DbError::Conflict.
                let update_at_col = update_at_column::<E>();
                let locked = <E as EntityTrait>::update_many()
                    .col_expr(update_at_col, Expr::value(new_ts))
                    .filter(
                        <E as EntityTrait>::PrimaryKey::into_column(
                            <E as EntityTrait>::PrimaryKey::iter()
                                .next()
                                .expect("entity must have a primary key"),
                        )
                        .eq(config.get_id()),
                    )
                    .filter(update_at_col.eq(incoming_ts))
                    .exec(txn)
                    .await?;
                if locked.rows_affected == 0 {
                    return Err(UpsertErr::Conflict);
                }
            }
            let mut active: E::ActiveModel = model.into_active_model();
            config.update(&mut active);
            let saved = active.update(txn).await?;
            Ok(Change { old, new: saved.into() })
        } else {
            let active: E::ActiveModel = config.into();
            // `?` converts through `From<DbErr>`: a primary-key race or WAL
            // lock/snapshot contention surfaces as `UpsertErr::Retry`, anything
            // else as `UpsertErr::Database`.
            let saved = active.insert(txn).await?;
            Ok(Change { old: None, new: saved.into() })
        }
    }
}

/// Locates the `update_at` column of an entity by name.
fn update_at_column<E: EntityTrait>() -> E::Column {
    E::Column::iter()
        .find(|col| col.as_str() == "update_at")
        .expect("entity must have an 'update_at' column")
}

/// Retryable SQLite result codes for concurrent-upsert races.
///
/// - `1555` SQLITE_CONSTRAINT_PRIMARYKEY: another txn inserted the same key
///   after our snapshot; retrying in a fresh txn turns it into an update.
/// - `5` / `517` SQLITE_BUSY / SQLITE_BUSY_SNAPSHOT: WAL write-lock contention
///   the busy_timeout handler cannot wait out; a fresh txn re-reads the snapshot.
///
/// Business unique keys (`2067` SQLITE_CONSTRAINT_UNIQUE, e.g. GeoSite `name`,
/// EnrolledDevice `mac`) are real conflicts, not races: deliberately not retried.
fn is_retryable_code(code: Option<&str>) -> bool {
    matches!(code, Some("1555") | Some("5") | Some("517"))
}

fn is_retryable_db_error(err: &DbErr) -> bool {
    let runtime = match err {
        DbErr::Exec(runtime) | DbErr::Query(runtime) => runtime,
        _ => return false,
    };
    match runtime {
        RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(db_err)) => {
            is_retryable_code(db_err.code().as_deref())
        }
        _ => false,
    }
}

fn retryable_code(err: &DbErr) -> Option<String> {
    let runtime = match err {
        DbErr::Exec(runtime) | DbErr::Query(runtime) => runtime,
        _ => return None,
    };
    match runtime {
        RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(db_err)) => {
            db_err.code().map(|c| c.to_string())
        }
        _ => None,
    }
}

fn upsert_retry_exhausted(code: String) -> DbError {
    tracing::warn!("write retry exhausted after {MAX_RETRIES} attempts (last db code {code})");
    DbError::Database(DbErr::Custom("concurrent write retry exhausted".to_string()))
}

async fn rollback_txn(txn: DatabaseTransaction) {
    if let Err(rollback_err) = txn.rollback().await {
        tracing::warn!("failed to rollback transaction: {rollback_err}");
    }
}

#[cfg(test)]
mod tests {
    use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
    use landscape_common::database::error::DbError;
    use landscape_common::database::repository::LandscapeDBStore;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::database::LandscapeStore;

    use crate::iface::repository::NetIfaceRepository;
    use crate::provider::LandscapeDBServiceProvider;
    use crate::writer::is_retryable_code;

    fn iface(name: &str) -> NetworkIfaceConfig {
        NetworkIfaceConfig::crate_bridge(name.to_string(), Some(IfaceZoneType::Lan))
    }

    fn repo(provider: &LandscapeDBServiceProvider) -> NetIfaceRepository {
        provider.iface_store()
    }

    #[tokio::test]
    async fn upsert_inserts_new_config_with_fresh_timestamp() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        let config = iface("br0");
        let stale_ts = config.get_update_at();

        let change = store.upsert(config).await.unwrap();

        assert!(change.old.is_none());
        assert_eq!(change.new.name, "br0");
        assert!(change.new.get_update_at() >= stale_ts);
    }

    #[tokio::test]
    async fn upsert_updates_existing_and_returns_old() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        store.upsert(iface("br0")).await.unwrap();

        let mut updated = iface("br0");
        updated.zone_type = IfaceZoneType::Wan;
        let change = store.upsert(updated).await.unwrap();

        let old = change.old.expect("old must be returned for existing row");
        assert_eq!(old.zone_type, IfaceZoneType::Lan);
        assert_eq!(change.new.zone_type, IfaceZoneType::Wan);
    }

    #[tokio::test]
    async fn checked_upsert_rejects_stale_timestamp() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        let saved = store.upsert(iface("br0")).await.unwrap().new;

        // resubmit with a stale update_at → conflict
        let mut stale = iface("br0");
        stale.set_update_at(saved.get_update_at() - 1.0);
        let result = store.checked_upsert(stale).await;

        assert!(matches!(result, Err(DbError::Conflict)));
    }

    #[tokio::test]
    async fn checked_upsert_succeeds_with_matching_timestamp() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        let saved = store.upsert(iface("br0")).await.unwrap().new;

        let mut update = saved.clone();
        update.zone_type = IfaceZoneType::Wan;
        let change = store.checked_upsert(update).await.unwrap();

        assert_eq!(change.old.unwrap().zone_type, IfaceZoneType::Lan);
        assert_eq!(change.new.zone_type, IfaceZoneType::Wan);
        assert!(change.new.get_update_at() > saved.get_update_at());
    }

    #[tokio::test]
    async fn checked_upsert_many_rolls_back_all_on_conflict() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        let saved = store.upsert(iface("br0")).await.unwrap().new;

        // first item is valid (id absent), second has the same id with a stale timestamp → whole txn rolls back
        let mut stale = iface("br0");
        stale.set_update_at(saved.get_update_at() - 1.0);
        let result = store.checked_upsert_many(vec![iface("br1"), stale]).await;

        assert!(matches!(result, Err(DbError::Conflict)));

        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1, "br1 must not survive the rollback");
        assert_eq!(all[0].name, "br0");
    }

    #[tokio::test]
    async fn upsert_many_applies_all_in_one_txn() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);

        let changes =
            store.upsert_many(vec![iface("br0"), iface("br1"), iface("br2")]).await.unwrap();

        assert_eq!(changes.len(), 3);
        assert!(changes.iter().all(|c| c.old.is_none()));
        assert_eq!(store.list().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn delete_and_get_returns_deleted_value() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        store.upsert(iface("br0")).await.unwrap();

        let deleted = store.delete_and_get("br0".to_string()).await.unwrap();

        assert_eq!(deleted.unwrap().name, "br0");
        assert!(store.find_by_id("br0".to_string()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_and_get_returns_none_for_missing() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);

        assert!(store.delete_and_get("nope".to_string()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn find_ids_keeps_input_order_and_skips_missing() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        store.upsert_many(vec![iface("br0"), iface("br1"), iface("br2")]).await.unwrap();

        let found = store
            .find_ids(vec!["br2".to_string(), "missing".to_string(), "br0".to_string()])
            .await
            .unwrap();

        let names: Vec<_> = found.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["br2", "br0"]);
    }

    #[tokio::test]
    async fn find_ids_keeps_duplicate_ids() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);
        store.upsert_many(vec![iface("br0"), iface("br1")]).await.unwrap();

        let found = store
            .find_ids(vec!["br0".to_string(), "br1".to_string(), "br0".to_string()])
            .await
            .unwrap();

        let names: Vec<_> = found.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["br0", "br1", "br0"]);
    }

    #[tokio::test]
    async fn find_ids_empty_input_returns_empty() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);

        assert!(store.find_ids(vec![]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_at_is_strictly_incremental_on_rapid_writes() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);

        // Back-to-back writes commonly land in the same millisecond; the second
        // version must still be strictly greater than the first.
        let first = store.upsert(iface("br0")).await.unwrap().new;
        let second = store.upsert(iface("br0")).await.unwrap().new;

        assert!(second.get_update_at() > first.get_update_at());

        // A stale client re-submitting the first version must lose.
        let mut stale = iface("br0");
        stale.set_update_at(first.get_update_at());
        assert!(matches!(store.checked_upsert(stale).await, Err(DbError::Conflict)));
    }

    #[tokio::test]
    async fn concurrent_upsert_of_same_new_id_both_succeed() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = repo(&provider);

        // One connection serializes the pool, but the second upsert must still
        // collapse into an update instead of surfacing a constraint error.
        let store_a = store.clone();
        let store_b = store.clone();
        let (a, b) = tokio::join!(store_a.upsert(iface("br0")), store_b.upsert(iface("br0")),);

        a.unwrap();
        b.unwrap();
        let all = store.list().await.unwrap();
        assert_eq!(all.len(), 1, "concurrent inserts of the same id must collapse into one row");
    }

    #[tokio::test]
    async fn concurrent_upsert_same_new_id_across_connections_collapses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent.db");

        // Smoke test, not a deterministic race assertion: retry classification
        // (1555/5/517) is deterministically covered by
        // `retryable_codes_cover_pk_races_and_wal_busy`; this only proves that
        // multi-connection contention converges to one row without 500s.
        let (a, b) = {
            let provider_a = LandscapeDBServiceProvider::file_test_db(&path).await;
            let provider_b = LandscapeDBServiceProvider::file_test_db(&path).await;
            let store_a = provider_a.iface_store();
            let store_b = provider_b.iface_store();
            tokio::join!(store_a.upsert(iface("br0")), store_b.upsert(iface("br0")),)
        };

        a.unwrap();
        b.unwrap();

        let provider = LandscapeDBServiceProvider::file_test_db(&path).await;
        let all = provider.iface_store().list().await.unwrap();
        assert_eq!(
            all.len(),
            1,
            "concurrent inserts across connections must collapse into one row"
        );
    }

    #[tokio::test]
    async fn concurrent_checked_upsert_on_existing_row_exactly_one_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checked.db");

        // Deterministic optimistic-lock assertion (the update path always bumps
        // the version strictly above the stored one): two writers submitting the
        // same base version must produce exactly one success and one
        // DbError::Conflict — a lost update would silently let both succeed.
        let base = {
            let provider = LandscapeDBServiceProvider::file_test_db(&path).await;
            provider.iface_store().upsert(iface("br0")).await.unwrap().new
        };
        let (a, b) = {
            let provider_a = LandscapeDBServiceProvider::file_test_db(&path).await;
            let provider_b = LandscapeDBServiceProvider::file_test_db(&path).await;
            let store_a = provider_a.iface_store();
            let store_b = provider_b.iface_store();
            tokio::join!(store_a.checked_upsert(base.clone()), store_b.checked_upsert(base.clone()),)
        };

        let successes = [&a, &b].iter().filter(|r| r.is_ok()).count();
        let conflicts = [&a, &b].iter().filter(|r| matches!(r, Err(DbError::Conflict))).count();
        assert_eq!(successes, 1, "exactly one writer must win");
        assert_eq!(conflicts, 1, "the loser must get DbError::Conflict, not a 500");

        let provider = LandscapeDBServiceProvider::file_test_db(&path).await;
        let all = provider.iface_store().list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert!(all[0].get_update_at() > base.get_update_at(), "version must be bumped");
    }

    #[test]
    fn retryable_codes_cover_pk_races_and_wal_busy() {
        // SQLITE_CONSTRAINT_PRIMARYKEY: concurrent insert of the same id
        assert!(is_retryable_code(Some("1555")));
        // SQLITE_BUSY / SQLITE_BUSY_SNAPSHOT: WAL write-lock/snapshot races
        assert!(is_retryable_code(Some("5")));
        assert!(is_retryable_code(Some("517")));
        // Business unique keys (GeoSite name, EnrolledDevice mac) are real
        // conflicts, not races: must NOT be retried
        assert!(!is_retryable_code(Some("2067")));
        assert!(!is_retryable_code(Some("19")));
        assert!(!is_retryable_code(None));
    }
}
