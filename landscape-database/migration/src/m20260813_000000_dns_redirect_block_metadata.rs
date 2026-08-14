use sea_orm_migration::prelude::*;

use crate::tables::dns_rule::DNSRedirectRuleConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DNSRedirectRuleConfigs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(DNSRedirectRuleConfigs::BlockMetadataQueries)
                            .boolean()
                            .default(Expr::value(true))
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DNSRedirectRuleConfigs::Table)
                    .drop_column(DNSRedirectRuleConfigs::BlockMetadataQueries)
                    .to_owned(),
            )
            .await
    }
}
