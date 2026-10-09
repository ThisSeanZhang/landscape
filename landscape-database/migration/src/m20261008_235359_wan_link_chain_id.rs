use sea_orm_migration::sea_orm::Statement;
use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::wan_link::WanLinks;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_INDEX: &str = "idx_wan_links_link_chain_id";

/// Standalone mirror of `landscape_common::wan_link::LINK_CHAIN_ID_MAX`.
const LINK_CHAIN_ID_MAX: i64 = 1023;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        // SQLite lacks `ADD COLUMN IF NOT EXISTS`; probe first so reruns stay clean.
        if !manager.has_column("wan_links", "link_chain_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(WanLinks::Table)
                        .add_column(small_unsigned(WanLinks::LinkChainId).not_null().default(0))
                        .to_owned(),
                )
                .await?;
        }

        // Fail inside the migration transaction rather than persist rows the
        // runtime validator would reject; recovery is deleting links on the old build.
        let unassigned: i64 = db
            .query_one(Statement::from_string(
                backend,
                "SELECT COUNT(*) FROM wan_links WHERE link_chain_id = 0".to_string(),
            ))
            .await?
            .expect("count query always returns a row")
            .try_get_by_index(0)?;
        if unassigned > LINK_CHAIN_ID_MAX {
            return Err(DbErr::Custom(format!(
                "cannot assign WAN link chain ids: {unassigned} links exceed the {}-link \
                 capacity; delete links on the old version and retry the upgrade",
                LINK_CHAIN_ID_MAX
            )));
        }

        // Hand out 1..N to unassigned rows before adding the unique index.
        db.execute(Statement::from_string(
            backend,
            "UPDATE wan_links \
             SET link_chain_id = ( \
                 SELECT sub.rn FROM ( \
                     SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn \
                     FROM wan_links WHERE link_chain_id = 0 \
                 ) AS sub \
                 WHERE sub.id = wan_links.id \
             ) \
             WHERE link_chain_id = 0"
                .to_string(),
        ))
        .await?;

        db.execute(Statement::from_string(
            backend,
            format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS {UNIQUE_INDEX} ON wan_links (link_chain_id)"
            ),
        ))
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        db.execute(Statement::from_string(backend, format!("DROP INDEX IF EXISTS {UNIQUE_INDEX}")))
            .await?;

        if manager.has_column("wan_links", "link_chain_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(WanLinks::Table)
                        .drop_column(WanLinks::LinkChainId)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend};

    use super::*;

    async fn test_db() -> sea_orm_migration::sea_orm::DatabaseConnection {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database
            .execute_unprepared(
                r#"
                CREATE TABLE wan_links (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    attach_iface_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    v4 TEXT NOT NULL,
                    pd TEXT NOT NULL,
                    nat TEXT NOT NULL,
                    firewall TEXT NOT NULL,
                    mss TEXT NOT NULL,
                    update_at REAL NOT NULL DEFAULT 0
                );
                INSERT INTO wan_links (id, name, attach_iface_name, kind, v4, pd, nat, firewall, mss, update_at)
                VALUES
                    ('00000000-0000-0000-0000-000000000001', 'wan0', 'wan0', '{"t":"ethernet"}', '{}', '{}', '{}', '{}', '{}', 1.0),
                    ('00000000-0000-0000-0000-000000000002', 'wan1', 'wan1', '{"t":"ethernet"}', '{}', '{}', '{}', '{}', '{}', 2.0);
                "#,
            )
            .await
            .unwrap();
        database
    }

    async fn chain_ids(db: &sea_orm_migration::sea_orm::DatabaseConnection) -> Vec<u16> {
        db.query_all(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT link_chain_id FROM wan_links ORDER BY link_chain_id".to_string(),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get_by_index::<i64>(0).unwrap() as u16)
        .collect()
    }

    #[tokio::test]
    async fn existing_rows_get_distinct_nonzero_chain_ids() {
        let db = test_db().await;

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        assert_eq!(chain_ids(&db).await, vec![1, 2]);
    }

    #[tokio::test]
    async fn down_up_roundtrip_keeps_rows() {
        let db = test_db().await;
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();
        Migration.down(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();

        assert_eq!(chain_ids(&db).await, vec![1, 2]);
    }

    async fn empty_db() -> sea_orm_migration::sea_orm::DatabaseConnection {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database
            .execute_unprepared(
                r#"
                CREATE TABLE wan_links (
                    id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    attach_iface_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    v4 TEXT NOT NULL,
                    pd TEXT NOT NULL,
                    nat TEXT NOT NULL,
                    firewall TEXT NOT NULL,
                    mss TEXT NOT NULL,
                    update_at REAL NOT NULL DEFAULT 0
                );
                "#,
            )
            .await
            .unwrap();
        database
    }

    async fn insert_links(db: &sea_orm_migration::sea_orm::DatabaseConnection, count: usize) {
        let values: Vec<String> = (0..count)
            .map(|i| {
                format!(
                    "('00000000-0000-0000-0000-{:012x}', 'wan{i}', 'wan{i}', \
                     '{{\"t\":\"ethernet\"}}', '{{}}', '{{}}', '{{}}', '{{}}', '{{}}', 1.0)",
                    i + 1
                )
            })
            .collect();
        let sql = format!(
            "INSERT INTO wan_links (id, name, attach_iface_name, kind, v4, pd, nat, firewall, mss, update_at) VALUES {}",
            values.join(", ")
        );
        db.execute_unprepared(&sql).await.unwrap();
    }

    #[tokio::test]
    async fn succeeds_at_full_capacity() {
        let db = empty_db().await;
        insert_links(&db, LINK_CHAIN_ID_MAX as usize).await;

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let mut expected: Vec<u16> = (1..=LINK_CHAIN_ID_MAX as u16).collect();
        expected.sort_unstable();
        assert_eq!(chain_ids(&db).await, expected);
    }

    #[tokio::test]
    async fn fails_loudly_beyond_capacity() {
        let db = empty_db().await;
        insert_links(&db, LINK_CHAIN_ID_MAX as usize + 1).await;

        let err = Migration.up(&SchemaManager::new(&db)).await.unwrap_err();

        let message = err.to_string();
        assert!(message.contains("exceed"), "unexpected error: {message}");
        assert!(message.contains("delete links"), "must tell the user how to recover: {message}");
        // The unique index must not survive a rejected migration.
        let index_count: i64 = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                format!(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = '{UNIQUE_INDEX}'"
                ),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(index_count, 0, "unique index must not be created on failure");
    }
}
