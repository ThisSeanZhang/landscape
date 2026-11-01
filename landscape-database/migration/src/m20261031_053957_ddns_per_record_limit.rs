use sea_orm_migration::prelude::*;

use crate::tables::ddns::DdnsJobs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DdnsJobs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DdnsJobs::MaxIpsPerRecord).unsigned().not_null().default(1),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DdnsJobs::Table)
                    .drop_column(DdnsJobs::MaxIpsPerRecord)
                    .to_owned(),
            )
            .await
    }
}
