use landscape_common::database::{repository::Repository, LandscapeDBTrait};
use landscape_common::dns::config::DnsUpstreamConfig;
use sea_orm::DatabaseConnection;

use crate::dns_upstream::entity::{
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

#[async_trait::async_trait]
impl LandscapeDBTrait for DnsUpstreamRepository {}

#[async_trait::async_trait]
impl Repository for DnsUpstreamRepository {
    type Model = DnsUpstreamConfigModel;
    type Entity = DnsUpstreamConfigEntity;
    type ActiveModel = DnsUpstreamConfigActiveModel;
    type Data = DnsUpstreamConfig;
    type Id = DBId;

    fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
