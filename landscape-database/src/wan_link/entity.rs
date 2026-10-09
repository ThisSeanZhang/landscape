use std::collections::HashSet;

use crate::repository::UpdateActiveModel;
use landscape_common::wan_link::{
    LINK_CHAIN_ID_MAX, LINK_CHAIN_ID_MIN, WanLinkConfig, allocate_link_chain_id,
};
use sea_orm::{ActiveValue, ActiveValue::Set, entity::prelude::*};
use serde::{Deserialize, Serialize};

use crate::{DBId, DBJson, DBTimestamp};

pub type WanLinkConfigModel = Model;
pub type WanLinkConfigEntity = Entity;
pub type WanLinkConfigActiveModel = ActiveModel;

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

/// Pick a free chain slot on insert: keep a free imported value, else take the
/// smallest free slot (error when the range is exhausted).
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

/// Chain id is immutable: force any update back to the stored value.
async fn freeze_link_chain_id<C>(active: &mut ActiveModel, db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let id = match &active.id {
        ActiveValue::Set(v) | ActiveValue::Unchanged(v) => Some(*v),
        ActiveValue::NotSet => None,
    };
    if let Some(id) = id
        && let Some(existing) = Entity::find_by_id(id).one(db).await?
    {
        active.link_chain_id = Set(existing.link_chain_id);
    }
    Ok(())
}

impl From<Model> for WanLinkConfig {
    fn from(entity: Model) -> Self {
        WanLinkConfig {
            id: entity.id,
            name: entity.name,
            attach_iface_name: entity.attach_iface_name,
            link_chain_id: entity.link_chain_id,
            kind: serde_json::from_value(entity.kind).unwrap(),
            v4: serde_json::from_value(entity.v4).unwrap(),
            pd: serde_json::from_value(entity.pd).unwrap(),
            nat: serde_json::from_value(entity.nat).unwrap(),
            firewall: serde_json::from_value(entity.firewall).unwrap(),
            mss: serde_json::from_value(entity.mss).unwrap(),
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
        active.kind = Set(serde_json::to_value(&self.kind).unwrap());
        active.v4 = Set(serde_json::to_value(&self.v4).unwrap());
        active.pd = Set(serde_json::to_value(&self.pd).unwrap());
        active.nat = Set(serde_json::to_value(&self.nat).unwrap());
        active.firewall = Set(serde_json::to_value(&self.firewall).unwrap());
        active.mss = Set(serde_json::to_value(&self.mss).unwrap());
        active.update_at = Set(self.update_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared(
            r#"
            CREATE TABLE wan_links (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                attach_iface_name TEXT NOT NULL,
                link_chain_id INTEGER NOT NULL DEFAULT 0,
                kind TEXT NOT NULL,
                v4 TEXT NOT NULL,
                pd TEXT NOT NULL,
                nat TEXT NOT NULL,
                firewall TEXT NOT NULL,
                mss TEXT NOT NULL,
                update_at REAL NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX idx_wan_links_link_chain_id ON wan_links (link_chain_id);
            "#,
        )
        .await
        .unwrap();
        db
    }

    fn config(attach: &str, chain: u16) -> WanLinkConfig {
        let mut config: WanLinkConfig = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "attach_iface_name": attach,
        }))
        .unwrap();
        config.link_chain_id = chain;
        config
    }

    #[tokio::test]
    async fn insert_assigns_smallest_free_slot() {
        let db = test_db().await;
        let a = ActiveModel::from(config("wan0", 0)).insert(&db).await.unwrap();
        let b = ActiveModel::from(config("wan1", 0)).insert(&db).await.unwrap();
        assert_eq!(a.link_chain_id, 1);
        assert_eq!(b.link_chain_id, 2);
    }

    #[tokio::test]
    async fn imported_valid_free_value_is_kept() {
        let db = test_db().await;
        let a = ActiveModel::from(config("wan0", 7)).insert(&db).await.unwrap();
        assert_eq!(a.link_chain_id, 7);
    }

    #[tokio::test]
    async fn update_freezes_chain_id() {
        let db = test_db().await;
        let mut cfg = config("wan0", 0);
        let saved = ActiveModel::from(cfg.clone()).insert(&db).await.unwrap();
        assert_eq!(saved.link_chain_id, 1);

        cfg.link_chain_id = 999;
        let updated = ActiveModel::from(cfg).update(&db).await.unwrap();
        assert_eq!(updated.link_chain_id, 1, "chain id is immutable after creation");
    }
}
