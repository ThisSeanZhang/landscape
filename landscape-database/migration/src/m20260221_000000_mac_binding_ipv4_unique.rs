use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        // Partial unique index: only enforce uniqueness when ipv4_int is not null.
        // This allows multiple bindings without an IP while preventing two MACs
        // from being assigned the same static IPv4 address.
        db.execute(sea_orm::Statement::from_string(
            manager.get_database_backend(),
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_mac_binding_ipv4_int \
             ON ip_mac_bindings (ipv4_int) WHERE ipv4_int IS NOT NULL",
        ))
        .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        db.execute(sea_orm::Statement::from_string(
            manager.get_database_backend(),
            "DROP INDEX IF EXISTS idx_mac_binding_ipv4_int",
        ))
        .await?;
        Ok(())
    }
}
