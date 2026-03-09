use landscape_common::config::gateway::HttpUpstreamRuleConfig;
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
