use landscape_common::database::error::DbError;
use landscape_common::database::LandscapeStore;
use landscape_common::wan_service::link::WanLinkConfig;
use sea_orm::error::RuntimeErr;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};

use super::entity::{Column, WanLinkActiveModel, WanLinkEntity, WanLinkModel};
use crate::repository::Repository;
use crate::DBId;

/// Bounded retries when two concurrent inserts pick the same chain id.
const CHAIN_ID_ALLOC_RETRIES: u32 = 5;

#[derive(Clone)]
pub struct WanLinkRepository {
    db: DatabaseConnection,
}

impl WanLinkRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_attach_iface_name(
        &self,
        attach_iface_name: &str,
    ) -> Result<Vec<WanLinkConfig>, DbError> {
        let models = WanLinkEntity::find()
            .filter(Column::AttachIfaceName.eq(attach_iface_name))
            .all(self.db())
            .await?;
        Ok(models.into_iter().map(Into::into).collect())
    }

    /// All links whose runtime net iface is the given one (attach iface for
    /// ethernet / native PPPoE, the ppp device for pppd links).
    pub async fn find_links_touching_iface(
        &self,
        net_iface: &str,
    ) -> Result<Vec<WanLinkConfig>, DbError> {
        // The wan_links table is tiny; filter in memory instead of relying
        // on a LIKE over a JSON column (whitespace- and wildcard-sensitive).
        Ok(self
            .list()
            .await?
            .into_iter()
            .filter(|link| link.net_iface_name() == net_iface)
            .collect())
    }

    /// Insert a brand-new link. `before_save` assigns the smallest free
    /// `link_chain_id` right before the INSERT; concurrent creates can pick the
    /// same slot, so a unique-index violation is retried with a fresh
    /// allocation (the retry re-reads the used set and takes the next free id).
    pub async fn insert_allocating(&self, config: WanLinkConfig) -> Result<WanLinkConfig, DbError> {
        retry_on_chain_id_conflict(|| self.set_model(config.clone())).await
    }

    /// Upsert that owns `link_chain_id`:
    /// - existing row → keep its stored id (immutable; `before_save` also frees it)
    /// - new row → submit 0 and let the insert path allocate
    pub async fn upsert_preserving_chain_id(
        &self,
        mut config: WanLinkConfig,
    ) -> Result<WanLinkConfig, DbError> {
        match LandscapeStore::find_by_id(self, config.id).await? {
            Some(existing) => {
                config.link_chain_id = existing.link_chain_id;
                self.checked_set(config).await
            }
            None => {
                config.link_chain_id = 0;
                self.insert_allocating(config).await
            }
        }
    }
}

/// Runs `attempt` until it succeeds or a link-chain-id unique violation
/// exhausts the retry budget. Any other error (optimistic-lock conflict, a
/// primary-key clash, …) is returned immediately.
async fn retry_on_chain_id_conflict<T, F, Fut>(mut attempt: F) -> Result<T, DbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, DbError>>,
{
    let mut retries = 0;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) if retries < CHAIN_ID_ALLOC_RETRIES && is_link_chain_id_conflict(&err) => {
                retries += 1;
                tokio::time::sleep(chain_id_retry_delay(retries)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// True only for the `wan_links.link_chain_id` unique-index violation, so a
/// primary-key clash is never mistaken for an allocatable retry.
fn is_link_chain_id_conflict(err: &DbError) -> bool {
    let DbError::Database(db_err) = err else {
        return false;
    };
    let runtime = match db_err {
        DbErr::Exec(runtime) | DbErr::Query(runtime) => runtime,
        _ => return false,
    };
    let RuntimeErr::SqlxError(sea_orm::sqlx::Error::Database(db_err)) = runtime else {
        return false;
    };
    // SQLite unique violation (2067); Postgres unique_violation (23505).
    if !matches!(db_err.code().as_deref(), Some("2067") | Some("23505")) {
        return false;
    }
    let message = db_err.message().to_ascii_lowercase();
    message.contains("link_chain_id") || message.contains("idx_wan_links_link_chain_id")
}

fn chain_id_retry_delay(retries: u32) -> std::time::Duration {
    std::time::Duration::from_millis(u64::from(retries).min(16) * 2)
}

crate::impl_repository!(
    WanLinkRepository,
    WanLinkModel,
    WanLinkEntity,
    WanLinkActiveModel,
    WanLinkConfig,
    DBId
);

#[cfg(test)]
mod tests {
    use super::{is_link_chain_id_conflict, retry_on_chain_id_conflict, CHAIN_ID_ALLOC_RETRIES};
    use crate::provider::LandscapeDBServiceProvider;
    use crate::repository::Repository;
    use crate::wan_link::entity::{WanLinkActiveModel, WanLinkEntity};
    use landscape_common::database::error::DbError;
    use landscape_common::wan_service::link::WanLinkConfig;
    use sea_orm::prelude::Uuid;
    use sea_orm::{ActiveValue, EntityTrait};

    async fn store_with_chain_id_1() -> (super::WanLinkRepository, Uuid) {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = provider.wan_link_store();
        let id = Uuid::new_v4();
        let stored = store
            .upsert_preserving_chain_id(WanLinkConfig {
                id,
                attach_iface_name: "wan0".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(stored.link_chain_id, 1);
        (store, id)
    }

    fn duplicate_chain_id_insert(chain_id: u16) -> WanLinkActiveModel {
        WanLinkConfig {
            id: Uuid::new_v4(),
            attach_iface_name: "dup".to_string(),
            link_chain_id: chain_id,
            ..Default::default()
        }
        .into()
    }

    #[tokio::test]
    async fn detects_only_link_chain_id_unique_violation() {
        let (store, existing_id) = store_with_chain_id_1().await;

        // Bypass `before_save` via `Entity::insert` to force a raw unique clash.
        let dup = duplicate_chain_id_insert(1);
        let err = WanLinkEntity::insert(dup).exec(store.db()).await.unwrap_err();
        assert!(is_link_chain_id_conflict(&DbError::Database(err)));

        // The same primary key is a different conflict and must not be retried.
        let mut pk = duplicate_chain_id_insert(2);
        pk.id = ActiveValue::Set(existing_id);
        let err = WanLinkEntity::insert(pk).exec(store.db()).await.unwrap_err();
        assert!(!is_link_chain_id_conflict(&DbError::Database(err)));
    }

    #[tokio::test]
    async fn retry_reallocates_once_then_succeeds() {
        let (store, _) = store_with_chain_id_1().await;
        let db = store.db().clone();
        let mut calls = 0u32;

        let result = retry_on_chain_id_conflict(|| {
            calls += 1;
            let attempt = calls;
            let db = db.clone();
            async move {
                if attempt == 1 {
                    let dup = duplicate_chain_id_insert(1);
                    let err = WanLinkEntity::insert(dup).exec(&db).await.unwrap_err();
                    Err(DbError::Database(err))
                } else {
                    Ok(WanLinkConfig {
                        attach_iface_name: "ok".to_string(),
                        ..Default::default()
                    })
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(calls, 2, "must retry exactly once after the collision");
    }

    #[tokio::test]
    async fn retry_gives_up_after_budget() {
        let (store, _) = store_with_chain_id_1().await;
        let db = store.db().clone();
        let mut calls = 0u32;

        let result: Result<WanLinkConfig, DbError> = retry_on_chain_id_conflict(|| {
            calls += 1;
            let db = db.clone();
            async move {
                let dup = duplicate_chain_id_insert(1);
                let err = WanLinkEntity::insert(dup).exec(&db).await.unwrap_err();
                Err(DbError::Database(err))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(calls, CHAIN_ID_ALLOC_RETRIES + 1);
    }

    #[tokio::test]
    async fn upsert_preserving_chain_id_allocates_then_keeps() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let store = provider.wan_link_store();

        let config = WanLinkConfig {
            id: Uuid::new_v4(),
            attach_iface_name: "wan0".to_string(),
            ..Default::default()
        };
        let first = store.upsert_preserving_chain_id(config.clone()).await.unwrap();
        assert_eq!(first.link_chain_id, 1);

        // Edit from the stored snapshot (so the optimistic lock matches).
        let mut edited = first.clone();
        edited.link_chain_id = 999;
        edited.name = "edited".to_string();
        let again = store.upsert_preserving_chain_id(edited).await.unwrap();
        assert_eq!(again.link_chain_id, 1, "existing link keeps its chain id");
        assert_eq!(again.name, "edited");
    }
}
