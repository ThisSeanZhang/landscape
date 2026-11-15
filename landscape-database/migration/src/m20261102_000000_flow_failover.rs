use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::flow_rule::FlowConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite lacks `ADD COLUMN IF NOT EXISTS`; probe first so reruns stay clean.
        if !manager.has_column("flow_configs", "failover").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(FlowConfigs::Table)
                        .add_column(
                            json(FlowConfigs::Failover).not_null().default(serde_json::json!({})),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_column("flow_configs", "failover").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(FlowConfigs::Table)
                        .drop_column(FlowConfigs::Failover)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};

    #[tokio::test]
    async fn upgrade_preserves_existing_rows_and_defaults_to_disabled() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("CREATE TABLE flow_configs (id TEXT PRIMARY KEY); INSERT INTO flow_configs VALUES ('existing');").await.unwrap();
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT failover FROM flow_configs WHERE id = 'existing'",
            ))
            .await
            .unwrap()
            .unwrap();
        let json: String = row.try_get_by_index(0).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            serde_json::json!({})
        );
        Migration.down(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        assert!(manager.has_column("flow_configs", "failover").await.unwrap());
    }
}
