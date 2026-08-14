use crate::repository::UpdateActiveModel;
use crate::{DBId, DBJson, DBTimestamp};
use landscape_common::dns::provider_profile::DnsProviderProfile;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

pub type DnsProviderProfileModel = Model;
pub type DnsProviderProfileEntity = Entity;
pub type DnsProviderProfileActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dns_provider_profiles")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub provider_config: DBJson,
    pub remark: Option<String>,
    pub ddns_default_ttl: Option<u32>,
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

impl From<Model> for DnsProviderProfile {
    fn from(entity: Model) -> Self {
        Self {
            id: entity.id,
            name: entity.name,
            provider_config: serde_json::from_value(entity.provider_config).unwrap(),
            remark: entity.remark,
            ddns_default_ttl: entity.ddns_default_ttl,
            update_at: entity.update_at,
        }
    }
}

impl From<DnsProviderProfile> for ActiveModel {
    fn from(val: DnsProviderProfile) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for DnsProviderProfile {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.provider_config = Set(serde_json::to_value(self.provider_config).unwrap());
        active.remark = Set(self.remark);
        active.ddns_default_ttl = Set(self.ddns_default_ttl);
        active.update_at = Set(self.update_at);
    }
}
