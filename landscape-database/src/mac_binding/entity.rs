use landscape_common::{
    database::repository::UpdateActiveModel, mac_binding::IpMacBinding, net::MacAddr,
};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type IpMacBindingModel = Model;
pub type IpMacBindingEntity = Entity;
pub type IpMacBindingActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_mac_bindings")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub update_at: DBTimestamp,
    pub name: String,
    pub fake_name: Option<String>,
    pub remark: Option<String>,
    pub mac: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub tag: DBJson,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for IpMacBinding {
    fn from(entity: Model) -> Self {
        IpMacBinding {
            id: entity.id,
            update_at: entity.update_at,
            name: entity.name,
            fake_name: entity.fake_name,
            remark: entity.remark,
            mac: MacAddr::from_str(&entity.mac).unwrap(),
            ipv4: entity.ipv4.map(|ip| ip.parse().unwrap()),
            ipv6: entity.ipv6.map(|ip| ip.parse().unwrap()),
            tag: serde_json::from_value(entity.tag).unwrap_or(vec![]),
        }
    }
}

impl Into<ActiveModel> for IpMacBinding {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel { id: Set(self.id), ..Default::default() };
        update(self, &mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for IpMacBinding {
    fn update(self, active: &mut ActiveModel) {
        update(self, active);
    }
}

pub(crate) fn update(data: IpMacBinding, active: &mut ActiveModel) {
    active.update_at = Set(data.update_at);
    active.name = Set(data.name);
    active.fake_name = Set(data.fake_name);
    active.remark = Set(data.remark);
    active.mac = Set(data.mac.to_string());
    active.ipv4 = Set(data.ipv4.map(|ip| ip.to_string()));
    active.ipv6 = Set(data.ipv6.map(|ip| ip.to_string()));
    active.tag = Set(serde_json::to_value(&data.tag).unwrap_or(serde_json::Value::Array(vec![])));
}
