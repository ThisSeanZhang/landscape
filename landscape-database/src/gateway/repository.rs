use landscape_common::sys_service::gateway::HttpUpstreamRuleConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    GatewayHttpUpstreamActiveModel, GatewayHttpUpstreamEntity, GatewayHttpUpstreamModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct GatewayHttpUpstreamRepository {
    db: DatabaseConnection,
}

impl GatewayHttpUpstreamRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    GatewayHttpUpstreamRepository,
    GatewayHttpUpstreamModel,
    GatewayHttpUpstreamEntity,
    GatewayHttpUpstreamActiveModel,
    HttpUpstreamRuleConfig,
    DBId
);

crate::impl_trivial_validator!(GatewayHttpUpstreamRepository, HttpUpstreamRuleConfig);
