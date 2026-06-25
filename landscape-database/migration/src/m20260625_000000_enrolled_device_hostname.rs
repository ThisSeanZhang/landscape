use sea_orm_migration::prelude::*;

use crate::tables::enrolled_device::EnrolledDevice;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(EnrolledDevice::Table)
                    .add_column(ColumnDef::new(EnrolledDevice::Hostname).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(EnrolledDevice::Table)
                    .drop_column(EnrolledDevice::Hostname)
                    .to_owned(),
            )
            .await
    }
}
