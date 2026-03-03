use sea_orm_migration::prelude::*;

use super::tables::cert::{CertAccounts, Certs};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CertAccounts::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CertAccounts::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(CertAccounts::Name).string().not_null())
                    .col(ColumnDef::new(CertAccounts::ProviderConfig).json().not_null())
                    .col(ColumnDef::new(CertAccounts::Email).string().not_null())
                    .col(ColumnDef::new(CertAccounts::AccountPrivateKey).text())
                    .col(ColumnDef::new(CertAccounts::AcmeAccountUrl).text())
                    .col(
                        ColumnDef::new(CertAccounts::UseStaging)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(CertAccounts::TermsAgreed)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(CertAccounts::Status)
                            .string()
                            .not_null()
                            .default("unregistered"),
                    )
                    .col(ColumnDef::new(CertAccounts::StatusMessage).text())
                    .col(ColumnDef::new(CertAccounts::UpdateAt).double().not_null().default(0.0))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Certs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Certs::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Certs::Name).string().not_null())
                    .col(ColumnDef::new(Certs::Domains).json().not_null())
                    .col(ColumnDef::new(Certs::Status).string().not_null().default("pending"))
                    .col(ColumnDef::new(Certs::PrivateKey).text())
                    .col(ColumnDef::new(Certs::Certificate).text())
                    .col(ColumnDef::new(Certs::CertificateChain).text())
                    .col(ColumnDef::new(Certs::ExpiresAt).double())
                    .col(ColumnDef::new(Certs::IssuedAt).double())
                    .col(ColumnDef::new(Certs::StatusMessage).text())
                    .col(ColumnDef::new(Certs::ForApi).boolean().not_null().default(false))
                    .col(ColumnDef::new(Certs::ForGateway).boolean().not_null().default(false))
                    .col(ColumnDef::new(Certs::CertType).json().not_null())
                    .col(ColumnDef::new(Certs::UpdateAt).double().not_null().default(0.0))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Certs::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(CertAccounts::Table).to_owned()).await?;
        Ok(())
    }
}
