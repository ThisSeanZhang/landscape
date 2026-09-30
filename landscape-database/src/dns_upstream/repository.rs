use landscape_common::dns::config::DnsUpstreamConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    DnsUpstreamConfigActiveModel, DnsUpstreamConfigEntity, DnsUpstreamConfigModel,
};
use crate::DBId;

#[derive(Clone)]
pub struct DnsUpstreamRepository {
    db: DatabaseConnection,
}

impl DnsUpstreamRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

crate::impl_repository!(
    DnsUpstreamRepository,
    DnsUpstreamConfigModel,
    DnsUpstreamConfigEntity,
    DnsUpstreamConfigActiveModel,
    DnsUpstreamConfig,
    DBId
);

crate::impl_trivial_validator!(DnsUpstreamRepository, DnsUpstreamConfig);
