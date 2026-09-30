use landscape_common::wan_service::wan_route::RouteWanServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    RouteWanServiceConfigActiveModel, RouteWanServiceConfigEntity, RouteWanServiceConfigModel,
};

#[derive(Clone)]
pub struct RouteWanServiceRepository {
    db: DatabaseConnection,
}

impl RouteWanServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    RouteWanServiceRepository,
    RouteWanServiceConfigModel,
    RouteWanServiceConfigEntity,
    RouteWanServiceConfigActiveModel,
    RouteWanServiceConfig,
    String
);

crate::impl_zone_validator!(RouteWanServiceRepository, RouteWanServiceConfig);
