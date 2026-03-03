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
    Status,
    StatusMessage,
    UpdateAt,
}

#[derive(DeriveIden)]
pub enum Certs {
    #[sea_orm(iden = "certs")]
    Table,
    Id,
    Name,
    Domains,
    Status,
    PrivateKey,
    Certificate,
    CertificateChain,
    ExpiresAt,
    IssuedAt,
    StatusMessage,
    CertType,
    ForApi,
    ForGateway,
    UpdateAt,
}
