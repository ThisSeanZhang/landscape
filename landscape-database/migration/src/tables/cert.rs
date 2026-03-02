use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum CertAccounts {
    #[sea_orm(iden = "cert_accounts")]
    Table,
    Id,
    Name,
    ProviderConfig,
    Email,
    AccountPrivateKey,
    AcmeAccountUrl,
    UseStaging,
    TermsAgreed,
    IsActive,
    Status,
    StatusMessage,
    UpdateAt,
}

#[derive(DeriveIden)]
pub enum CertOrders {
    #[sea_orm(iden = "cert_orders")]
    Table,
    Id,
    Name,
    AccountId,
    Domains,
    ChallengeType,
    KeyType,
    Status,
    PrivateKey,
    Certificate,
    CertificateChain,
    AcmeOrderUrl,
    ExpiresAt,
    IssuedAt,
    AutoRenew,
    RenewBeforeDays,
    StatusMessage,
    UpdateAt,
}
