use sea_orm_migration::{prelude::*, schema::*};

use crate::tables::dns_rule::DNSRedirectRuleConfigs;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(DNSRedirectRuleConfigs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(DNSRedirectRuleConfigs::Id).uuid().primary_key())
                    .col(string_null(DNSRedirectRuleConfigs::Remark))
                    .col(ColumnDef::new(DNSRedirectRuleConfigs::Enable).boolean().default(false))
                    .col(json_null(DNSRedirectRuleConfigs::MatchRules))
                    .col(json_null(DNSRedirectRuleConfigs::ResultInfo))
                    .col(json_null(DNSRedirectRuleConfigs::ApplyFlows))
                    .col(double(DNSRedirectRuleConfigs::UpdateAt).default(0))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(DNSRedirectRuleConfigs::Table).to_owned()).await
    }
}
