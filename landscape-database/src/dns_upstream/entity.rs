use landscape_common::{database::repository::UpdateActiveModel, dns::upstream::DnsUpstreamConfig};
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
        }
    }
}

/// DnsUpstreamConfig -> ActiveModel
impl Into<ActiveModel> for DnsUpstreamConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        self.update(&mut active);
        active
    }
}

/// UpdateActiveModel 实现
impl UpdateActiveModel<ActiveModel> for DnsUpstreamConfig {
    fn update(self, active: &mut ActiveModel) {
        active.remark = Set(self.remark);
        active.mode = Set(serde_json::to_value(self.mode).unwrap().into());
        active.ips = Set(serde_json::to_value(self.ips).unwrap().into());
        active.port = Set(self.port);
        active.update_at = Set(self.update_at);
    }
}
