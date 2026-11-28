use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::flow_rule::FlowConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite lacks `ADD COLUMN IF NOT EXISTS`; probe first so reruns stay clean.
        if !manager.has_column("flow_configs", "balance_mode").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(FlowConfigs::Table)
                        .add_column(
                            json(FlowConfigs::BalanceMode)
                                .not_null()
                                .default(serde_json::json!({ "t": "dst_ip" })),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_column("flow_configs", "balance_mode").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(FlowConfigs::Table)
                        .drop_column(FlowConfigs::BalanceMode)
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
                CREATE TABLE flow_configs (
                    id TEXT PRIMARY KEY NOT NULL,
                    enable INTEGER NOT NULL,
                    flow_id INTEGER NOT NULL,
                    flow_match_rules TEXT NOT NULL,
                    packet_handle_iface_name TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    remark TEXT NOT NULL,
                    update_at REAL NOT NULL DEFAULT 0
                );
                INSERT INTO flow_configs (id, enable, flow_id, flow_match_rules, packet_handle_iface_name, name, remark, update_at)
                VALUES
                    ('00000000-0000-0000-0000-000000000001', 1, 5, '[]', '[]', 'flow5', 'test', 1.0);
                "#,
            )
            .await
            .unwrap();
        database
    }

    async fn balance_mode_raw(
        db: &sea_orm_migration::sea_orm::DatabaseConnection,
    ) -> Option<String> {
        // Errors (column absent after down()) map to None.
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT balance_mode FROM flow_configs".to_string(),
            ))
            .await
            .ok()??;
        row.try_get_by_index::<String>(0).ok()
    }

    #[tokio::test]
    async fn existing_rows_get_default_json_object() {
        let db = test_db().await;

        Migration.up(&SchemaManager::new(&db)).await.unwrap();

        let raw = balance_mode_raw(&db).await.expect("column exists after up");
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, serde_json::json!({ "t": "dst_ip" }));
    }

    #[tokio::test]
    async fn up_is_idempotent_and_down_up_roundtrip_keeps_rows() {
        let db = test_db().await;
        let manager = SchemaManager::new(&db);

        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        Migration.down(&manager).await.unwrap();
        assert_eq!(balance_mode_raw(&db).await, None, "column dropped by down()");
        Migration.up(&manager).await.unwrap();

        let raw = balance_mode_raw(&db).await.expect("column restored after re-up");
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, serde_json::json!({ "t": "dst_ip" }));
    }
}
