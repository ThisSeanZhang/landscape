use std::collections::HashMap;

use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::database::validator::StoreValidator;
use landscape_common::service::ServiceConfigError;
use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
use sea_orm::DatabaseConnection;

use super::entity::{WanLinkConfigActiveModel, WanLinkConfigEntity, WanLinkConfigModel};
use crate::DBId;

#[derive(Clone)]
pub struct WanLinkRepository {
    db: DatabaseConnection,
}

impl WanLinkRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Maps every stored link's uuid to its net iface name (see
    /// [`WanLinkConfig::section_iface_name`]); callers resolve references
    /// strictly through [`resolve_wan_link_name`].
    pub async fn net_iface_map(&self) -> Result<HashMap<DBId, String>, DbError> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .map(|link| (link.id, link.section_iface_name().to_string()))
            .collect())
    }
}

/// Strict wan-link reference resolution: the link must exist, otherwise
/// [`ServiceConfigError::InvalidConfig`] (healing already happened in the
/// migration). Returns the net iface name to mirror back.
pub(crate) fn resolve_wan_link_name<'a>(
    map: &'a HashMap<DBId, String>,
    link_id: DBId,
    ref_desc: &str,
) -> Result<&'a str, ServiceConfigError> {
    map.get(&link_id).map(String::as_str).ok_or_else(|| ServiceConfigError::InvalidConfig {
        reason: format!("{ref_desc} references unknown wan link {link_id}"),
    })
}

/// Optional-binding variant for the static NAT mappings: resolves
/// `wan_link_id` and dual-writes the `wan_iface_name` mirror;
/// `None` = unbound and clears the mirror.
pub(crate) async fn resolve_wan_link_binding(
    db: sea_orm::DatabaseConnection,
    wan_link_id: &mut Option<DBId>,
    wan_iface_name: &mut Option<String>,
) -> Result<(), ServiceConfigError> {
    match *wan_link_id {
        None => {
            if wan_iface_name.is_some() {
                *wan_iface_name = None;
            }
            Ok(())
        }
        Some(link_id) => {
            let links = WanLinkRepository::new(db)
                .net_iface_map()
                .await
                .map_err(ServiceConfigError::internal)?;
            let iface = resolve_wan_link_name(&links, link_id, "static NAT mapping WAN binding")?;
            if wan_iface_name.as_deref() != Some(iface) {
                *wan_iface_name = Some(iface.to_string());
            }
            Ok(())
        }
    }
}

crate::impl_repository!(
    WanLinkRepository,
    WanLinkConfigModel,
    WanLinkConfigEntity,
    WanLinkConfigActiveModel,
    WanLinkConfig,
    DBId
);

fn is_ethernet_class(kind: &WanLinkKind) -> bool {
    !matches!(kind, WanLinkKind::Pppd { .. })
}

#[async_trait::async_trait]
impl StoreValidator<WanLinkConfig> for WanLinkRepository {
    async fn check_zone(&self, config: &WanLinkConfig) -> Result<(), ServiceConfigError> {
        crate::validator::ZoneChecker::new(self.db.clone()).check(config).await
    }

    /// Cross-link rules (same-table old rows + the iface table). The
    /// netlink-dependent checks (live attach iface / live ppp device) stay
    /// in the webserver handler; see `validate_wan_link` there.
    async fn validate_cross(&self, config: &mut WanLinkConfig) -> Result<(), ServiceConfigError> {
        let others: Vec<WanLinkConfig> = self
            .list()
            .await
            .map_err(ServiceConfigError::internal)?
            .into_iter()
            .filter(|link| link.id != config.id)
            .collect();

        for link in &others {
            if link.attach_iface_name == config.attach_iface_name {
                // At most one ethernet-class link (ethernet / pppoe_native) per
                // attach iface; PPPD links may stack alongside.
                if is_ethernet_class(&config.kind) && is_ethernet_class(&link.kind) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "attach interface '{}' already has an ethernet-class WAN link",
                            config.attach_iface_name
                        ),
                    });
                }
                // Native PPPoE and PPPD cannot share an attach iface (legacy rule).
                if (matches!(config.kind, WanLinkKind::Pppd { .. })
                    && matches!(link.kind, WanLinkKind::PppoeNative { .. }))
                    || (matches!(config.kind, WanLinkKind::PppoeNative { .. })
                        && matches!(link.kind, WanLinkKind::Pppd { .. }))
                {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "interface '{}' already uses native PPPoE; disable it before enabling PPPD-based PPPoE",
                            config.attach_iface_name
                        ),
                    });
                }
            }

            if let (
                WanLinkKind::Pppd { ppp_iface_name, .. },
                WanLinkKind::Pppd { ppp_iface_name: existing, .. },
            ) = (&config.kind, &link.kind)
                && ppp_iface_name == existing
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("PPPoE interface name '{ppp_iface_name}' is already in use"),
                });
            }

            // The attach iface itself must not be another link's ppp device.
            if let WanLinkKind::Pppd { ppp_iface_name, .. } = &link.kind
                && *ppp_iface_name == config.attach_iface_name
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "attach interface '{}' cannot be an existing PPP interface",
                        config.attach_iface_name
                    ),
                });
            }
        }

        // A new ppp device must not collide with a managed iface row. An
        // unchanged ppp_iface_name is skipped: the row belongs to the link's
        // own ppp device (the store keeps an iface config row for it).
        if let WanLinkKind::Pppd { ppp_iface_name, .. } = &config.kind {
            let unchanged_name = self
                .find_by_id(config.id)
                .await
                .map_err(ServiceConfigError::internal)?
                .is_some_and(|old| {
                    matches!(&old.kind, WanLinkKind::Pppd { ppp_iface_name: n, .. } if n == ppp_iface_name)
                });
            let existing_pppd = others.iter().any(|link| {
                matches!(&link.kind, WanLinkKind::Pppd { ppp_iface_name: n, .. } if n == ppp_iface_name)
            });
            let managed_iface_exists =
                crate::iface::repository::NetIfaceRepository::new(self.db.clone())
                    .find_by_id(ppp_iface_name.clone())
                    .await
                    .map_err(ServiceConfigError::internal)?
                    .is_some();
            if !existing_pppd && !unchanged_name && managed_iface_exists {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "PPPoE interface '{ppp_iface_name}' conflicts with an existing interface"
                    ),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use landscape_common::config_service::iface::{
        CreateDevType, IfaceZoneType, NetworkIfaceConfig, ServiceKind, WifiMode,
    };
    use landscape_common::database::error::DbError;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::service::ServiceConfigError;
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn iface(name: &str, zone: IfaceZoneType) -> NetworkIfaceConfig {
        NetworkIfaceConfig {
            name: name.to_string(),
            create_dev_type: CreateDevType::NoNeedToCreate,
            controller_name: None,
            zone_type: zone,
            enable_in_boot: true,
            wifi_mode: WifiMode::default(),
            xps_rps: None,
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

    async fn setup() -> LandscapeDBServiceProvider {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        provider.iface_store().upsert(iface("eth0", IfaceZoneType::Wan)).await.unwrap();
        provider.iface_store().upsert(iface("eth1", IfaceZoneType::Wan)).await.unwrap();
        provider
    }

    #[tokio::test]
    async fn second_ethernet_class_link_on_same_iface_rejected() {
        let provider = setup().await;
        let repo = provider.wan_link_store();
        repo.upsert(link(Uuid::new_v4(), "eth0", WanLinkKind::Ethernet)).await.unwrap();

        let result = repo.checked_upsert(link(Uuid::new_v4(), "eth0", WanLinkKind::Ethernet)).await;
        assert!(result.is_err(), "two ethernet-class links on one attach iface");
    }

    #[tokio::test]
    async fn pppd_stacks_alongside_ethernet_link() {
        let provider = setup().await;
        let repo = provider.wan_link_store();
        repo.upsert(link(Uuid::new_v4(), "eth0", WanLinkKind::Ethernet)).await.unwrap();

        let result = repo.checked_upsert(link(Uuid::new_v4(), "eth0", pppd("ppp0"))).await;
        assert!(result.is_ok(), "PPPD may stack alongside an ethernet-class link");
    }

    #[tokio::test]
    async fn pppd_and_native_pppoe_on_same_iface_rejected() {
        let provider = setup().await;
        let repo = provider.wan_link_store();
        let native = WanLinkKind::PppoeNative {
            username: "u".to_string(),
            password: "p".to_string(),
            requested_mru: 1480,
            ac_name: None,
            lcp_echo_interval: None,
            redial_backoff_base_secs: None,
        };
        repo.upsert(link(Uuid::new_v4(), "eth0", native)).await.unwrap();

        let result = repo.checked_upsert(link(Uuid::new_v4(), "eth0", pppd("ppp0"))).await;
        assert!(result.is_err(), "PPPD and native PPPoE cannot share an attach iface");
    }

    #[tokio::test]
    async fn duplicate_ppp_iface_name_rejected() {
        let provider = setup().await;
        let repo = provider.wan_link_store();
        repo.upsert(link(Uuid::new_v4(), "eth0", pppd("ppp0"))).await.unwrap();

        let result = repo.checked_upsert(link(Uuid::new_v4(), "eth1", pppd("ppp0"))).await;
        assert!(result.is_err(), "ppp iface names must be unique across links");
    }

    #[tokio::test]
    async fn attach_iface_equal_to_foreign_ppp_device_rejected() {
        let provider = setup().await;
        let repo = provider.wan_link_store();
        repo.upsert(link(Uuid::new_v4(), "eth0", pppd("ppp0"))).await.unwrap();
        // Register the ppp device as a managed WAN iface so the zone check
        // passes and the cross-link rule is what rejects the write.
        provider.iface_store().upsert(iface("ppp0", IfaceZoneType::Wan)).await.unwrap();

        let result = repo.checked_upsert(link(Uuid::new_v4(), "ppp0", WanLinkKind::Ethernet)).await;
        assert!(result.is_err(), "attach iface must not be another link's ppp device");
    }

    #[tokio::test]
    async fn non_wan_attach_iface_rejected_with_zone_mismatch() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        provider.iface_store().upsert(iface("br0", IfaceZoneType::Lan)).await.unwrap();

        let err = match provider
            .wan_link_store()
            .checked_upsert(link(Uuid::new_v4(), "br0", WanLinkKind::Ethernet))
            .await
        {
            Err(err) => err,
            Ok(change) => panic!("links only live on WAN ifaces, got {change:?}"),
        };
        assert!(
            matches!(
                err,
                DbError::Validation(ServiceConfigError::ZoneMismatch {
                    service_name: ServiceKind::WanLink,
                    ..
                })
            ),
            "expected service.zone_mismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn ppp_name_conflicting_with_managed_iface_rejected_on_create() {
        let provider = setup().await;
        provider.iface_store().upsert(iface("ppp0", IfaceZoneType::Undefined)).await.unwrap();

        let result = provider
            .wan_link_store()
            .checked_upsert(link(Uuid::new_v4(), "eth0", pppd("ppp0")))
            .await;
        assert!(result.is_err(), "a new ppp device must not collide with a managed iface row");
    }

    /// Regression: updating a running PPPD link (whose ppp device has an
    /// iface-config row) with an unchanged ppp_iface_name must pass; the
    /// row belongs to the link's own ppp device.
    #[tokio::test]
    async fn unchanged_ppp_name_allows_update_despite_managed_row() {
        let provider = setup().await;
        let repo = provider.wan_link_store();
        let id = Uuid::new_v4();
        repo.upsert(link(id, "eth0", pppd("ppp0"))).await.unwrap();

        // The link's own ppp device got managed (iface config row exists).
        provider.iface_store().upsert(iface("ppp0", IfaceZoneType::Wan)).await.unwrap();

        // Echo back the stored update_at like a real client, change a field.
        let mut old = repo.find_by_id(id).await.unwrap().unwrap();
        old.name = "renamed".to_string();
        let result = repo.checked_upsert(old).await;
        assert!(result.is_ok(), "unchanged ppp_iface_name is the link's own device");

        // Renaming onto a managed name is still rejected.
        let mut old = repo.find_by_id(id).await.unwrap().unwrap();
        old.kind = pppd("eth1");
        let result = repo.checked_upsert(old).await;
        assert!(result.is_err(), "a renamed ppp device colliding with a managed iface is rejected");
    }
}
