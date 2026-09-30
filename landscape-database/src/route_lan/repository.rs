use landscape_common::lan_service::lan_route::RouteLanServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    RouteLanServiceConfigActiveModel, RouteLanServiceConfigEntity, RouteLanServiceConfigModel,
};

#[derive(Clone)]
pub struct RouteLanServiceRepository {
    db: DatabaseConnection,
}

impl RouteLanServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    RouteLanServiceRepository,
    RouteLanServiceConfigModel,
    RouteLanServiceConfigEntity,
    RouteLanServiceConfigActiveModel,
    RouteLanServiceConfig,
    String
);

crate::impl_zone_validator!(RouteLanServiceRepository, RouteLanServiceConfig);
