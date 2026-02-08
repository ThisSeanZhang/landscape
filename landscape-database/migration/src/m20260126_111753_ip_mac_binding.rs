use sea_orm_migration::prelude::*;

use super::tables::mac_binding::IpMacBinding;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IpMacBinding::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IpMacBinding::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(IpMacBinding::UpdateAt).double().not_null())
                    .col(ColumnDef::new(IpMacBinding::Name).string().not_null())
                    .col(ColumnDef::new(IpMacBinding::FakeName).string())
                    .col(ColumnDef::new(IpMacBinding::Remark).string())
                    .col(ColumnDef::new(IpMacBinding::Mac).string().not_null())
                    .col(ColumnDef::new(IpMacBinding::Ipv4).string())
                    .col(ColumnDef::new(IpMacBinding::Ipv6).string())
                    .col(ColumnDef::new(IpMacBinding::Tag).json().not_null())
                    .to_owned(),
            )
            .await?;

        // Create unique index for MAC address
        manager
            .create_index(
                Index::create()
                    .name("idx-mac-binding-mac")
                    .table(IpMacBinding::Table)
                    .col(IpMacBinding::Mac)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(IpMacBinding::Table).to_owned()).await
    }
}
