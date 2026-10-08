use landscape_common::database::validator::StoreValidator;
use landscape_common::lan_service::lan_ipv6::{LanIPv6ServiceConfigV2, PrefixParentSource};
use landscape_common::service::ServiceConfigError;
use sea_orm::DatabaseConnection;

use super::entity::{
    LanIPv6ServiceConfigV2ActiveModel, LanIPv6ServiceConfigV2Entity, LanIPv6ServiceConfigV2Model,
};
use crate::wan_link::repository::{WanLinkRepository, resolve_wan_link_name};

#[derive(Clone)]
pub struct LanIPv6V2ServiceRepository {
    db: DatabaseConnection,
}

impl LanIPv6V2ServiceRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
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

#[async_trait::async_trait]
impl StoreValidator<LanIPv6ServiceConfigV2> for LanIPv6V2ServiceRepository {
    async fn check_zone(&self, config: &LanIPv6ServiceConfigV2) -> Result<(), ServiceConfigError> {
        crate::validator::ZoneChecker::new(self.db.clone()).check(config).await
    }

    /// PD prefix-group parents reference wan links by uuid
    /// (`parent.link_id`); resolve strictly and refresh the
    /// `depend_iface` mirror. A nil id is rejected.
    async fn validate_cross(
        &self,
        config: &mut LanIPv6ServiceConfigV2,
    ) -> Result<(), ServiceConfigError> {
        if !config
            .config
            .prefix_groups
            .iter()
            .any(|group| matches!(group.parent, PrefixParentSource::Pd { .. }))
        {
            return Ok(());
        }
        let links = WanLinkRepository::new(self.db.clone())
            .net_iface_map()
            .await
            .map_err(ServiceConfigError::internal)?;
        for group in &mut config.config.prefix_groups {
            let PrefixParentSource::Pd { link_id, depend_iface, .. } = &mut group.parent else {
                continue;
            };
            if link_id.is_nil() {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "PD parent must reference a wan link (link_id is missing)".to_string(),
                });
            }
            let iface = resolve_wan_link_name(&links, *link_id, "PD parent")?;
            if depend_iface != iface {
                *depend_iface = iface.to_string();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
    use landscape_common::database::store::ConfigStore;
    use landscape_common::lan_service::lan_ipv6::{
        IPv6ServiceMode, LanIPv6ConfigV2, LanIPv6ServiceConfigV2, LanPrefixGroupConfig,
        PrefixParentSource, RaPrefixConfig, RouterFlags,
    };
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn lan_iface(name: &str) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name: name.to_string(),
            create_dev_type: Default::default(),
            controller_name: None,
            zone_type: IfaceZoneType::Lan,
            enable_in_boot: true,
            wifi_mode: Default::default(),
            xps_rps: None,
            update_at: 0.0,
        }
    }

    fn link(id: Uuid, attach: &str, kind: WanLinkKind) -> WanLinkConfig {
        WanLinkConfig {
            id,
            name: String::new(),
            attach_iface_name: attach.to_string(),
            kind,
            v4: Default::default(),
            pd: Default::default(),
            nat: Default::default(),
            firewall: Default::default(),
            mss: Default::default(),
            update_at: 0.0,
        }
    }

    fn pppd(ppp: &str) -> WanLinkKind {
        WanLinkKind::Pppd {
            ppp_iface_name: ppp.to_string(),
            peer_id: "peer".to_string(),
            password: "pass".to_string(),
            ac: None,
            plugin: Default::default(),
        }
    }

    async fn setup() -> LandscapeDBServiceProvider {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        provider.iface_store().upsert(lan_iface("br0")).await.unwrap();
        provider.wan_link_store().upsert(link(Uuid::new_v4(), "eth9", pppd("ppp9"))).await.unwrap();
        provider
    }

    fn pd_config(link_id: Uuid, depend_iface: &str) -> LanIPv6ServiceConfigV2 {
        LanIPv6ServiceConfigV2 {
            iface_name: "br0".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "g0".to_string(),
                    parent: PrefixParentSource::Pd {
                        link_id,
                        depend_iface: depend_iface.to_string(),
                        expected_pd_len_snapshot: 60,
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

    fn parent_depend_iface(config: &LanIPv6ServiceConfigV2) -> &str {
        match &config.config.prefix_groups[0].parent {
            PrefixParentSource::Pd { depend_iface, .. } => depend_iface,
            other => panic!("expected pd parent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pd_parent_mirror_is_rewritten_from_the_link() {
        let provider = setup().await;
        let link_id = provider
            .wan_link_store()
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|link| link.attach_iface_name == "eth9")
            .map(|link| link.id)
            .unwrap();

        // a stale mirror on a valid reference is refreshed
        let saved = provider
            .lan_ipv6_v2_service_store()
            .checked_upsert(pd_config(link_id, "stale-name"))
            .await
            .unwrap()
            .new;
        assert_eq!(parent_depend_iface(&saved), "ppp9");
    }

    #[tokio::test]
    async fn pd_parent_with_nil_link_id_is_rejected() {
        let provider = setup().await;

        let result = provider
            .lan_ipv6_v2_service_store()
            .checked_upsert(pd_config(Uuid::nil(), "ppp9"))
            .await;
        assert!(result.is_err(), "a missing link_id must be rejected");
    }

    #[tokio::test]
    async fn pd_parent_with_unknown_link_id_is_rejected() {
        let provider = setup().await;

        let result = provider
            .lan_ipv6_v2_service_store()
            .checked_upsert(pd_config(Uuid::new_v4(), "ppp9"))
            .await;
        assert!(result.is_err(), "an unknown link_id must be rejected");
    }

    #[tokio::test]
    async fn config_without_pd_parents_skips_the_link_query() {
        let provider = setup().await;
        let mut config = pd_config(Uuid::nil(), "ppp9");
        config.config.prefix_groups.clear();

        let result = provider.lan_ipv6_v2_service_store().checked_upsert(config).await;
        assert!(result.is_ok(), "no PD parents → nothing to resolve");
    }
}
