use landscape_common::flow::service::FlowWanServiceConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    FlowWanServiceConfigActiveModel, FlowWanServiceConfigEntity, FlowWanServiceConfigModel,
};

#[derive(Clone)]
pub struct FlowWanServiceRepository {
    db: DatabaseConnection,
}

impl FlowWanServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    FlowWanServiceRepository,
    FlowWanServiceConfigModel,
    FlowWanServiceConfigEntity,
    FlowWanServiceConfigActiveModel,
    FlowWanServiceConfig,
    String
);

crate::impl_trivial_validator!(FlowWanServiceRepository, FlowWanServiceConfig);
