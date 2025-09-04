use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::dns_rule::DNSUpstreamConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DNSUpstreamConfigs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(DNSUpstreamConfigs::Id).uuid().not_null().primary_key())
                    .col(string_null(DNSUpstreamConfigs::Remark))
                    .col(json_null(DNSUpstreamConfigs::Mode))
                    .col(json_null(DNSUpstreamConfigs::Ips))
                    .col(ColumnDef::new(DNSUpstreamConfigs::Port).unsigned().null())
                    .col(double(DNSUpstreamConfigs::UpdateAt).default(0))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(DNSUpstreamConfigs::Table).to_owned()).await
    }
}
