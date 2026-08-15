use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::dns_rule::DNSUpstreamConfigs;

/// Source-address binding moved from per-rule (`dns_rule_configs.bind_config`,
/// unused) onto the upstream config.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DNSUpstreamConfigs::Table)
                    .add_column_if_not_exists(json(DNSUpstreamConfigs::BindConfig).default("{}"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(DNSUpstreamConfigs::Table)
                    .drop_column(DNSUpstreamConfigs::BindConfig)
                    .to_owned(),
            )
            .await
    }
}
