use crate::repository::UpdateActiveModel;
use landscape_common::{
    net::MacAddr,
    wan_service::ipv6_pd::{IPV6PDConfig, IPV6PDServiceConfig},
};
use sea_orm::{entity::prelude::*, ActiveValue::Set};
use serde::{Deserialize, Serialize};

use crate::DBTimestamp;

pub type DHCPv6ClientConfigModel = Model;
pub type DHCPv6ClientConfigEntity = Entity;
pub type DHCPv6ClientConfigActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "dhcp_v6_client_configs")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub iface_name: String,
    pub enable: bool,

    pub mac: String,
    pub expected_pd_len: u8,
    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for IPV6PDServiceConfig {
    fn from(entity: Model) -> Self {
        let config = IPV6PDConfig {
            mac: MacAddr::from_str(&entity.mac).unwrap(),
            expected_pd_len: entity.expected_pd_len,
        };
        IPV6PDServiceConfig {
            iface_name: entity.iface_name,
            enable: entity.enable,
            update_at: entity.update_at,
            config,
        }
    }
}

impl Into<ActiveModel> for IPV6PDServiceConfig {
    fn into(self) -> ActiveModel {
        let mut active = ActiveModel {
            iface_name: Set(self.iface_name.clone()),
            ..Default::default()
        };
        self.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for IPV6PDServiceConfig {
    fn update(self, active: &mut ActiveModel) {
        active.enable = Set(self.enable);
        active.mac = Set(self.config.mac.to_string());
        active.expected_pd_len = Set(self.config.expected_pd_len);
        active.update_at = Set(self.update_at);
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::ActiveValue::Set;

    use super::{ActiveModel, Model};
    use landscape_common::wan_service::ipv6_pd::IPV6PDServiceConfig;

    #[test]
    fn expected_pd_len_round_trips_through_entity_mapping() {
        let config: IPV6PDServiceConfig = Model {
            iface_name: "wan0".to_string(),
            enable: true,
            mac: "02:00:00:00:00:01".to_string(),
            expected_pd_len: 64,
            update_at: 123.0,
        }
        .into();

        assert_eq!(config.config.expected_pd_len, 64);

        let active: ActiveModel = config.into();
        assert_eq!(active.expected_pd_len, Set(64));
    }
}
