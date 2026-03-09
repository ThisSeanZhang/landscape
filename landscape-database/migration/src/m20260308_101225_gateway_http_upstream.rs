use sea_orm_migration::prelude::*;

use super::tables::gateway::GatewayHttpUpstreamRules;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(GatewayHttpUpstreamRules::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(GatewayHttpUpstreamRules::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(GatewayHttpUpstreamRules::Name).string().not_null())
                    .col(
                        ColumnDef::new(GatewayHttpUpstreamRules::Enable)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(ColumnDef::new(GatewayHttpUpstreamRules::MatchRule).json().not_null())
                    .col(ColumnDef::new(GatewayHttpUpstreamRules::Upstream).json().not_null())
                    .col(
                        ColumnDef::new(GatewayHttpUpstreamRules::UpdateAt)
                            .double()
                            .not_null()
                            .default(0.0),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(GatewayHttpUpstreamRules::Table).to_owned()).await?;
        Ok(())
    }
}
