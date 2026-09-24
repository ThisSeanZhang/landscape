use std::collections::HashSet;

use crate::repository::UpdateActiveModel;
use crate::{DBId, DBJson, DBTimestamp};
use landscape_common::wan_service::link::{
    allocate_link_chain_id, WanLinkConfig, LINK_CHAIN_ID_MAX, LINK_CHAIN_ID_MIN,
};
use sea_orm::{entity::prelude::*, ActiveValue, ActiveValue::Set};
use serde::{Deserialize, Serialize};

pub type WanLinkModel = Model;
pub type WanLinkEntity = Entity;
pub type WanLinkActiveModel = ActiveModel;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "wan_links")]
#[cfg_attr(feature = "postgres", sea_orm(schema_name = "public"))]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: DBId,
    pub name: String,
    pub attach_iface_name: String,
    pub link_chain_id: u16,
    pub kind: DBJson,
    pub v4: DBJson,
    pub pd: DBJson,
    pub nat: DBJson,
    pub firewall: DBJson,
    pub mss: DBJson,

    pub update_at: DBTimestamp,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        if insert {
            if self.id.is_not_set() {
                self.id = Set(Uuid::new_v4());
            }
            assign_link_chain_id(&mut self, db).await?;
        } else {
            freeze_link_chain_id(&mut self, db).await?;
        }
        Ok(self)
    }
}

/// Assign a unique chain id right before the first insert: keep an imported
/// valid value when it is free, otherwise take the smallest free slot.
/// Fails when `1..=1023` is fully used.
async fn assign_link_chain_id<C>(active: &mut ActiveModel, db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let used: HashSet<u16> =
        Entity::find().all(db).await?.into_iter().map(|m| m.link_chain_id).collect();

    let current = match &active.link_chain_id {
        ActiveValue::Set(v) | ActiveValue::Unchanged(v) => *v,
        ActiveValue::NotSet => 0,
    };

    let assigned =
        if (LINK_CHAIN_ID_MIN..=LINK_CHAIN_ID_MAX).contains(&current) && !used.contains(&current) {
            current
        } else {
            allocate_link_chain_id(used).ok_or_else(|| {
                DbErr::Custom(format!(
                    "no free WAN link chain id in [{LINK_CHAIN_ID_MIN}, {LINK_CHAIN_ID_MAX}]"
                ))
            })?
        };

    active.link_chain_id = Set(assigned);
    Ok(())
}

/// Chain id is immutable after creation: any update is forced back to the
/// value currently stored for the row.
async fn freeze_link_chain_id<C>(active: &mut ActiveModel, db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let id = match &active.id {
        ActiveValue::Set(v) | ActiveValue::Unchanged(v) => Some(*v),
        ActiveValue::NotSet => None,
    };
    if let Some(id) = id {
        if let Some(existing) = Entity::find_by_id(id).one(db).await? {
            active.link_chain_id = Set(existing.link_chain_id);
        }
    }
    Ok(())
}

/// Decode a JSON section column into T, falling back to the section default
/// on corrupt data instead of panicking on the read path.
fn section_or_default<T: Default + serde::de::DeserializeOwned>(
    column: &str,
    raw: serde_json::Value,
) -> T {
    match serde_json::from_value(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("wan_links.{column} is corrupt ({e}); using section default");
            T::default()
        }
    }
}

impl From<Model> for WanLinkConfig {
    fn from(entity: Model) -> Self {
        Self {
            id: entity.id,
            name: entity.name,
            attach_iface_name: entity.attach_iface_name,
            link_chain_id: entity.link_chain_id,
            kind: section_or_default("kind", entity.kind),
            v4: section_or_default("v4", entity.v4),
            pd: section_or_default("pd", entity.pd),
            nat: section_or_default("nat", entity.nat),
            firewall: section_or_default("firewall", entity.firewall),
            mss: section_or_default("mss", entity.mss),
            update_at: entity.update_at,
        }
    }
}

impl From<WanLinkConfig> for ActiveModel {
    fn from(val: WanLinkConfig) -> Self {
        let mut active = ActiveModel { id: Set(val.id), ..Default::default() };
        val.update(&mut active);
        active
    }
}

impl UpdateActiveModel<ActiveModel> for WanLinkConfig {
    fn update(self, active: &mut ActiveModel) {
        active.name = Set(self.name);
        active.attach_iface_name = Set(self.attach_iface_name);
        active.link_chain_id = Set(self.link_chain_id);
        active.kind = Set(serde_json::to_value(self.kind).unwrap());
        active.v4 = Set(serde_json::to_value(self.v4).unwrap());
        active.pd = Set(serde_json::to_value(self.pd).unwrap());
        active.nat = Set(serde_json::to_value(self.nat).unwrap());
        active.firewall = Set(serde_json::to_value(self.firewall).unwrap());
        active.mss = Set(serde_json::to_value(self.mss).unwrap());
        active.update_at = Set(self.update_at)
    }
}

#[cfg(test)]
mod tests {
    use landscape_common::wan_service::link::{
        WanLinkConfig, WanLinkKindConfig, WanV4Config, WanV4Model,
    };
    use sea_orm::prelude::Uuid;

    use super::Model;

    /// Locks the JSON shapes produced by the m20260922 backfill migration to
    /// the `WanLinkConfig` serde contract — the migration builds JSON by hand
    /// (the migration crate does not depend on landscape-common), so any drift
    /// between the two sides must fail here.
    #[test]
    fn migration_backfill_json_decodes_into_config() {
        let model = Model {
            id: Uuid::new_v4(),
            name: "ppp0".to_string(),
            attach_iface_name: "wan0".to_string(),
            link_chain_id: 7,
            kind: serde_json::json!({
                "t": "pppd",
                "ppp_iface_name": "ppp0",
                "peer_id": "user",
                "password": "pass",
                "ac": "ac1",
                "plugin": "rp_pppoe",
            }),
            v4: serde_json::json!({
                "enable": true,
                "model": {"t": "ipcp", "default_router": true},
            }),
            pd: serde_json::json!({
                "enable": true,
                "mac": "02:00:00:00:00:01",
                "expected_pd_len": 56,
            }),
            nat: serde_json::json!({
                "enable": false,
                "tcp_range": null,
                "udp_range": null,
                "icmp_in_range": null,
            }),
            firewall: serde_json::json!({"enable": false}),
            mss: serde_json::json!({"enable": true, "clamp_size": 1452}),
            update_at: 42.0,
        };

        let config: WanLinkConfig = model.into();
        assert_eq!(config.attach_iface_name, "wan0");
        assert_eq!(config.link_chain_id, 7);
        assert!(matches!(config.kind, WanLinkKindConfig::Pppd { .. }));
        assert!(matches!(config.v4.model, WanV4Model::Ipcp { .. }));
        assert!(config.v4.enable);
        assert!(config.pd.enable);
        assert_eq!(config.pd.expected_pd_len, Some(56));
        assert!(config.mss.enable);
        assert_eq!(config.mss.clamp_size, Some(1452));
        assert!(config.active());
    }

    #[test]
    fn corrupt_section_falls_back_to_default() {
        let model = Model {
            id: Uuid::new_v4(),
            name: "x".to_string(),
            attach_iface_name: "wan0".to_string(),
            link_chain_id: 1,
            kind: serde_json::json!({"t": "ethernet"}),
            v4: serde_json::json!({"enable": "not-a-bool"}),
            pd: serde_json::json!({"enable": false, "mac": "00:00:00:00:00:00", "expected_pd_len": null}),
            nat: serde_json::json!({"enable": false, "tcp_range": null, "udp_range": null, "icmp_in_range": null}),
            firewall: serde_json::json!({"enable": false}),
            mss: serde_json::json!({"enable": false, "clamp_size": null}),
            update_at: 0.0,
        };

        let config: WanLinkConfig = model.into();
        assert_eq!(config.v4, WanV4Config::default());
    }
}
