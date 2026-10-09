use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::wan_link::WanLinks;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite lacks `ADD COLUMN IF NOT EXISTS`; probe first so reruns stay clean.
        if !manager.has_column("wan_links", "health_check").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(WanLinks::Table)
                        .add_column(
                            json(WanLinks::HealthCheck).not_null().default(serde_json::json!({})),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_column("wan_links", "health_check").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(WanLinks::Table)
                        .drop_column(WanLinks::HealthCheck)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

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
                    link_chain_id INTEGER NOT NULL DEFAULT 0,
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
                    ('00000000-0000-0000-0000-000000000001', 'wan0', 'wan0', '{"t":"ethernet"}', '{}', '{}', '{}', '{}', '{}', 1.0);
                "#,
            )
            .await
            .unwrap();
        database
    }

    async fn health_section(db: &sea_orm_migration::sea_orm::DatabaseConnection) -> Option<String> {
        // Errors (column absent after down()) map to None.
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT health_check FROM wan_links".to_string(),
            ))
            .await
            .ok()??;
        row.try_get_by_index::<String>(0).ok()
    }

    #[tokio::test]
    async fn existing_rows_get_empty_default_section() {
        let db = test_db().await;

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let section = health_section(&db).await.expect("column exists after up");
        let parsed: serde_json::Value = serde_json::from_str(&section).unwrap();
        assert_eq!(parsed, serde_json::json!({}));
    }

    #[tokio::test]
    async fn up_is_idempotent_and_down_up_roundtrip_keeps_rows() {
        let db = test_db().await;
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        Migration.down(&manager).await.unwrap();
        assert_eq!(health_section(&db).await, None, "column dropped by down()");
        Migration.up(&manager).await.unwrap();

        let count: i64 = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) FROM wan_links".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index(0)
            .unwrap();
        assert_eq!(count, 1, "rows survive the roundtrip");
    }
}
