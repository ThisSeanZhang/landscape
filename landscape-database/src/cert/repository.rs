use landscape_common::cert::order::CertConfig;
use sea_orm::DatabaseConnection;

use super::entity::{CertActiveModel, CertEntity, CertModel};
use crate::DBId;

#[derive(Clone)]
pub struct CertRepository {
    db: DatabaseConnection,
}

impl CertRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(CertRepository, CertModel, CertEntity, CertActiveModel, CertConfig, DBId);
