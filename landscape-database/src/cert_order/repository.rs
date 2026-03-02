use landscape_common::cert::order::CertOrderConfig;
use sea_orm::DatabaseConnection;

use super::entity::{CertOrderActiveModel, CertOrderEntity, CertOrderModel};
use crate::DBId;

#[derive(Clone)]
pub struct CertOrderRepository {
    db: DatabaseConnection,
}

impl CertOrderRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    CertOrderRepository,
    CertOrderModel,
    CertOrderEntity,
    CertOrderActiveModel,
    CertOrderConfig,
    DBId
);
