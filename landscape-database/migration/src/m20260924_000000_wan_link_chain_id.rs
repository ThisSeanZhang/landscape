use sea_orm_migration::sea_orm::Statement;
use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::wan_link::WanLinks;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_INDEX: &str = "idx_wan_links_link_chain_id";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        manager
            .alter_table(
                Table::alter()
                    .table(WanLinks::Table)
                    .add_column_if_not_exists(
                        small_unsigned(WanLinks::LinkChainId).not_null().default(0),
                    )
                    .to_owned(),
            )
            .await?;

        // Existing rows all default to 0; hand out 1..N in a deterministic
        // order before the unique index is added. A correlated subquery keeps
        // this portable across SQLite and Postgres without decoding the PK.
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

        manager
            .alter_table(
                Table::alter().table(WanLinks::Table).drop_column(WanLinks::LinkChainId).to_owned(),
            )
            .await
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
        .map(|row| {
            let id: i64 = row.try_get_by_index(0).unwrap();
            id as u16
        })
        .collect()
    }

    #[tokio::test]
    async fn existing_rows_get_distinct_nonzero_chain_ids() {
        let db = test_db().await;

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        assert_eq!(chain_ids(&db).await, vec![1, 2]);
    }
}
