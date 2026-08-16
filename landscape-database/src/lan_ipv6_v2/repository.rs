use landscape_common::database::repository::LandscapeDBStore;
use landscape_common::lan_service::lan_ipv6::{
    validate_global_prefix_conflicts, LanIPv6Error, LanIPv6ServiceConfigV2,
};
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, IntoActiveModel, TransactionTrait,
};

use super::entity::{
    LanIPv6ServiceConfigV2ActiveModel, LanIPv6ServiceConfigV2Entity, LanIPv6ServiceConfigV2Model,
};
use crate::repository::UpdateActiveModel;

#[derive(Clone)]
pub struct LanIPv6V2ServiceRepository {
    db: DatabaseConnection,
}

impl LanIPv6V2ServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Atomically validate global prefix-slot ownership and persist one interface config.
    pub async fn checked_set_with_global_validation(
        &self,
        mut pending: LanIPv6ServiceConfigV2,
    ) -> Result<LanIPv6ServiceConfigV2, LanIPv6Error> {
        let txn =
            self.db.begin().await.map_err(landscape_common::database::error::DbError::from)?;
        let result = async {
            let models = LanIPv6ServiceConfigV2Entity::find()
                .all(&txn)
                .await
                .map_err(landscape_common::database::error::DbError::from)?;
            let existing = models.iter().find(|model| model.iface_name == pending.iface_name);

            if existing.is_some_and(|model| {
                (model.update_at - pending.get_update_at()).abs() > f64::EPSILON
            }) {
                return Err(LanIPv6Error::ConfigConflict);
            }

            let configs = models.iter().cloned().map(Into::into).collect::<Vec<_>>();
            validate_global_prefix_conflicts(&pending, &configs, None)?;

            pending.set_update_at(landscape_common::utils::time::get_f64_timestamp());
            let saved = if let Some(existing) = existing {
                let mut active = existing.clone().into_active_model();
                pending.clone().update(&mut active);
                active
                    .update(&txn)
                    .await
                    .map_err(landscape_common::database::error::DbError::from)?
                    .into()
            } else {
                let active: LanIPv6ServiceConfigV2ActiveModel = pending.into();
                active
                    .insert(&txn)
                    .await
                    .map_err(landscape_common::database::error::DbError::from)?
                    .into()
            };

            Ok(saved)
        }
        .await;

        match result {
            Ok(saved) => {
                txn.commit().await.map_err(landscape_common::database::error::DbError::from)?;
                Ok(saved)
            }
            Err(error) => {
                if let Err(rollback_error) = txn.rollback().await {
                    tracing::warn!(%rollback_error, "failed to roll back LAN IPv6 config write");
                }
                Err(error)
            }
        }
    }
}

crate::impl_repository!(
    LanIPv6V2ServiceRepository,
    LanIPv6ServiceConfigV2Model,
    LanIPv6ServiceConfigV2Entity,
    LanIPv6ServiceConfigV2ActiveModel,
    LanIPv6ServiceConfigV2,
    String
);

#[cfg(test)]
mod tests {
    use landscape_common::lan_service::lan_ipv6::{
        IPv6ServiceMode, LanIPv6ConfigV2, LanIPv6Error, LanIPv6ServiceConfigV2,
        LanPrefixGroupConfig, PrefixParentSource, RaPrefixConfig, RouterFlags,
    };

    use crate::provider::LandscapeDBServiceProvider;

    fn slaac_config(iface_name: &str) -> LanIPv6ServiceConfigV2 {
        LanIPv6ServiceConfigV2 {
            iface_name: iface_name.to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: format!("group-{iface_name}"),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 1,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        }
    }

    #[tokio::test]
    async fn concurrent_conflicting_slots_only_persist_once() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let left_store = provider.lan_ipv6_v2_service_store();
        let right_store = left_store.clone();

        let (left, right) = tokio::join!(
            left_store.checked_set_with_global_validation(slaac_config("lan0")),
            right_store.checked_set_with_global_validation(slaac_config("lan1")),
        );

        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let error = left.err().or_else(|| right.err()).unwrap();
        assert!(matches!(error, LanIPv6Error::PrefixSlotOverlap(_)));

        use landscape_common::database::LandscapeStore;
        let persisted = left_store.list().await.unwrap();
        assert_eq!(persisted.len(), 1);
    }
}
