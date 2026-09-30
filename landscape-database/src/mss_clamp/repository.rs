use landscape_common::wan_service::mss_clamp::MSSClampServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    MSSClampServiceConfigActiveModel, MSSClampServiceConfigEntity, MSSClampServiceConfigModel,
};

#[derive(Clone)]
pub struct MssClampServiceRepository {
    db: DatabaseConnection,
}

impl MssClampServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    MssClampServiceRepository,
    MSSClampServiceConfigModel,
    MSSClampServiceConfigEntity,
    MSSClampServiceConfigActiveModel,
    MSSClampServiceConfig,
    String
);

crate::impl_zone_validator!(MssClampServiceRepository, MSSClampServiceConfig);
