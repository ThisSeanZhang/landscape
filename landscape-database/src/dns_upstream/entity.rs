use crate::repository::UpdateActiveModel;
use landscape_common::dns::config::DnsUpstreamConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type DnsUpstreamConfigModel = Model;
pub type DnsUpstreamConfigEntity = Entity;
pub type DnsUpstreamConfigActiveModel = ActiveModel;
pub type DnsUpstreamConfigColumn = Column;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dns_upstream_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,

    pub remark: String,

    pub mode: DBJson,

    pub ips: DBJson,

    pub port: Option<u16>,

    pub enable_ip_validation: Option<bool>,

    /// Source-address binding for connections to this upstream
    pub bind_config: DBJson,

    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert && self.id.is_not_set() {
            self.id = Set(Uuid::new_v4());
        }
        Ok(self)
    }
}

/// Model -> DnsUpstreamConfig
impl From<Model> for DnsUpstreamConfig {
    fn from(entity: Model) -> Self {
        DnsUpstreamConfig {
            id: entity.id,
            remark: entity.remark,
            mode: serde_json::from_value(entity.mode).unwrap(),
            ips: serde_json::from_value(entity.ips).unwrap(),
            port: entity.port,
            update_at: entity.update_at,
            enable_ip_validation: entity.enable_ip_validation,
            bind_config: serde_json::from_value(entity.bind_config).unwrap(),
        }
    }
}

/// DnsUpstreamConfig -> ActiveModel
impl From<DnsUpstreamConfig> for ActiveModel {
    fn from(val: DnsUpstreamConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

/// UpdateActiveModel 实现
impl UpdateActiveModel<ActiveModel> for DnsUpstreamConfig {
    fn update(self, active: &mut ActiveModel) {
        active.remark = Set(self.remark);
        active.mode = Set(serde_json::to_value(self.mode).unwrap());
        active.ips = Set(serde_json::to_value(self.ips).unwrap());
        active.port = Set(self.port);
        active.enable_ip_validation = Set(self.enable_ip_validation);
        active.bind_config = Set(serde_json::to_value(self.bind_config).unwrap());
        active.update_at = Set(self.update_at);
    }
}
