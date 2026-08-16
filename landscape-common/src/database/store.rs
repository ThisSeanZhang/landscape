use std::fmt::Debug;

use super::error::DbError;

/// Values before and after a write operation; `old` is `None` for pure inserts.
/// Read within the same transaction as the write, so `old` is guaranteed to be
/// the row that was actually replaced (useful for rollback or event payloads).
#[derive(Debug, Clone)]
pub struct Change<D> {
    pub old: Option<D>,
    pub new: D,
}

impl<D> Change<D> {
    pub fn old(&self) -> Option<&D> {
        self.old.as_ref()
    }

    pub fn current(&self) -> &D {
        &self.new
    }
}

/// Next-generation storage interface: write operations return `Change` and batch
/// writes are all-or-nothing in a single transaction.
///
/// Runs in parallel with the legacy `LandscapeStore` and will be removed once all
/// domains are migrated. Read methods (`find_by_id`/`list`) are still provided by
/// the legacy trait to avoid method-name ambiguity when both traits are in scope.
///
/// # Semantics
///
/// - `update_at` is the optimistic-lock version, managed through the shared
///   [`LandscapeDBStore`](super::repository::LandscapeDBStore) trait; every
///   entity must have an `update_at` field. Every write refreshes it to a value
///   strictly greater than the stored one, so clients holding a stale value
///   always fail `checked_upsert` with `DbError::Conflict`. Clients must echo
///   the `update_at` they received back unchanged.
/// - Concurrent `upsert`s of the same id are safe: the loser of a simultaneous
///   insert becomes an update instead of surfacing a constraint error.
/// - `checked_upsert`/`checked_upsert_many` compare and write atomically
///   (`WHERE update_at = ?`), so a lost update is impossible even under concurrency.
#[async_trait::async_trait]
pub trait ConfigStore: Send + Sync {
    type Data: Send + Sync + Debug;
    type Id: Send + Sync + Debug;

    /// Blind upsert; `update_at` is refreshed server-side without conflict checking.
    async fn upsert(&self, config: Self::Data) -> Result<Change<Self::Data>, DbError>;

    /// Optimistic-lock write: the stored `update_at` must match the incoming one,
    /// otherwise `DbError::Conflict`; on success `update_at` is refreshed to now.
    async fn checked_upsert(&self, config: Self::Data) -> Result<Change<Self::Data>, DbError>;

    /// Batch blind upsert in a single transaction; any failure rolls back everything.
    async fn upsert_many(
        &self,
        configs: Vec<Self::Data>,
    ) -> Result<Vec<Change<Self::Data>>, DbError>;

    /// Batch optimistic-lock write in a single transaction; any failure rolls back everything.
    async fn checked_upsert_many(
        &self,
        configs: Vec<Self::Data>,
    ) -> Result<Vec<Change<Self::Data>>, DbError>;

    /// Read and delete within a transaction, returning the deleted value.
    async fn delete_and_get(&self, id: Self::Id) -> Result<Option<Self::Data>, DbError>;

    /// Batch read by id with a single `IN` query; preserves input order and
    /// duplicates, silently skips missing ids.
    async fn find_ids(&self, ids: Vec<Self::Id>) -> Result<Vec<Self::Data>, DbError>;
}
