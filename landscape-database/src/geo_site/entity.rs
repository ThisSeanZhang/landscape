use crate::repository::UpdateActiveModel;
use landscape_common::config_service::geo::GeoSiteSourceConfig;
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type GeoSiteConfigModel = Model;
pub type GeoSiteConfigEntity = Entity;
pub type GeoSiteConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "geo_site_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub update_at: DBTimestamp,
    pub name: String,
    pub enable: bool,
    #[sea_orm(column_type = "Json")]
    pub source: DBJson,
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

impl From<Model> for GeoSiteSourceConfig {
    fn from(entity: Model) -> Self {
        GeoSiteSourceConfig {
            id: entity.id,
            update_at: entity.update_at,
            name: entity.name,
            enable: entity.enable,
            source: serde_json::from_value(entity.source).unwrap(),
        }
    }
}

impl From<GeoSiteSourceConfig> for ActiveModel {
    fn from(val: GeoSiteSourceConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for GeoSiteSourceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.update_at = Set(self.update_at);
        active.name = Set(self.name);
        active.enable = Set(self.enable);
        active.source = Set(serde_json::to_value(self.source).unwrap());
    }
}
