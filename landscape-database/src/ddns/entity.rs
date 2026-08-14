use crate::repository::UpdateActiveModel;
use crate::{DBId, DBJson, DBTimestamp};
use landscape_common::ddns::DdnsJob;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

pub type DdnsJobModel = Model;
pub type DdnsJobEntity = Entity;
pub type DdnsJobActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ddns_jobs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub enable: bool,
    pub source: DBJson,
    pub zone_name: String,
    pub provider_profile_id: DBId,
    pub ttl: Option<u32>,
    pub records: DBJson,
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

impl From<Model> for DdnsJob {
    fn from(entity: Model) -> Self {
        Self {
            id: entity.id,
            name: entity.name,
            enable: entity.enable,
            sources: serde_json::from_value(entity.source).unwrap_or_default(),
            zone_name: entity.zone_name,
            provider_profile_id: entity.provider_profile_id,
            ttl: entity.ttl,
            records: serde_json::from_value(entity.records).unwrap_or_default(),
            update_at: entity.update_at,
        }
    }
}

impl From<DdnsJob> for ActiveModel {
    fn from(val: DdnsJob) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for DdnsJob {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.enable = Set(self.enable);
        active.source = Set(serde_json::to_value(self.sources).unwrap());
        active.zone_name = Set(self.zone_name);
        active.provider_profile_id = Set(self.provider_profile_id);
        active.ttl = Set(self.ttl);
        active.records = Set(serde_json::to_value(self.records).unwrap());
        active.update_at = Set(self.update_at);
    }
}
