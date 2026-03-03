use sea_orm_migration::prelude::*;

use super::tables::cert::{CertAccounts, CertOrders};

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
                    .table(CertOrders::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(CertOrders::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(CertOrders::Name).string().not_null())
                    .col(ColumnDef::new(CertOrders::AccountId).uuid().not_null())
                    .col(ColumnDef::new(CertOrders::Domains).json().not_null())
                    .col(ColumnDef::new(CertOrders::ChallengeType).json().not_null())
                    .col(
                        ColumnDef::new(CertOrders::KeyType)
                            .string()
                            .not_null()
                            .default("ecdsa_p256"),
                    )
                    .col(ColumnDef::new(CertOrders::Status).string().not_null().default("pending"))
                    .col(ColumnDef::new(CertOrders::PrivateKey).text())
                    .col(ColumnDef::new(CertOrders::Certificate).text())
                    .col(ColumnDef::new(CertOrders::CertificateChain).text())
                    .col(ColumnDef::new(CertOrders::AcmeOrderUrl).text())
                    .col(ColumnDef::new(CertOrders::ExpiresAt).double())
                    .col(ColumnDef::new(CertOrders::IssuedAt).double())
                    .col(ColumnDef::new(CertOrders::AutoRenew).boolean().not_null().default(false))
                    .col(
                        ColumnDef::new(CertOrders::RenewBeforeDays)
                            .integer()
                            .not_null()
                            .default(30),
                    )
                    .col(ColumnDef::new(CertOrders::StatusMessage).text())
                    .col(ColumnDef::new(CertOrders::UpdateAt).double().not_null().default(0.0))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(CertOrders::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(CertAccounts::Table).to_owned()).await?;
        Ok(())
    }
}
