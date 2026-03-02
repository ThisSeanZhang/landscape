use landscape_common::cert::account::CertAccountConfig;
use sea_orm::DatabaseConnection;

use super::entity::{CertAccountActiveModel, CertAccountEntity, CertAccountModel};
use crate::DBId;

#[derive(Clone)]
pub struct CertAccountRepository {
    db: DatabaseConnection,
}

impl CertAccountRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    CertAccountRepository,
    CertAccountModel,
    CertAccountEntity,
    CertAccountActiveModel,
    CertAccountConfig,
    DBId
);
