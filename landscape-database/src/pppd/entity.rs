use crate::repository::UpdateActiveModel;
use landscape_common::wan_service::pppd::{PPPDConfig, PPPDServiceConfig};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBTimestamp;

pub type PPPDServiceConfigModel = Model;
pub type PPPDServiceConfigEntity = Entity;
pub type PPPDServiceConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "pppd_service_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub attach_iface_name: String,
    pub enable: bool,

    pub default_route: bool,
    pub peer_id: String,
    pub password: String,

    pub update_at: DBTimestamp,

    /// Since 0.8.1
    pub ac: Option<String>,

    pub plugin: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for PPPDServiceConfig {
    fn from(entity: Model) -> Self {
        PPPDServiceConfig {
            iface_name: entity.iface_name,
            attach_iface_name: entity.attach_iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
            pppd_config: PPPDConfig {
                default_route: entity.default_route,
                peer_id: entity.peer_id,
                password: entity.password,
                ac: entity.ac,
                plugin: serde_json::from_value(serde_json::Value::String(entity.plugin))
                    .unwrap_or_default(),
            },
        }
    }
}

impl From<PPPDServiceConfig> for ActiveModel {
    fn from(val: PPPDServiceConfig) -> Self {
        let mut active = ActiveModel {
            iface_name: Set(val.iface_name.clone()),
            ..Default::default()
        };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for PPPDServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.attach_iface_name = Set(self.attach_iface_name);
        active.enable = Set(self.enable);
        active.default_route = Set(self.pppd_config.default_route);
        active.peer_id = Set(self.pppd_config.peer_id);
        active.password = Set(self.pppd_config.password);
        active.update_at = Set(self.update_at);
        active.ac = Set(self.pppd_config.ac);
        active.plugin = Set(serde_json::to_value(&self.pppd_config.plugin)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "rp_pppoe".to_string()));
    }
}
