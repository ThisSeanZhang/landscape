use sea_orm_migration::prelude::*;

use crate::tables::flow_rule::FlowConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(FlowConfigs::Table)
                    .add_column(ColumnDef::new(FlowConfigs::Name).string().not_null().default(""))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter().table(FlowConfigs::Table).drop_column(FlowConfigs::Name).to_owned(),
            )
            .await
    }
}
