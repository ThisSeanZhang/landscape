use std::collections::HashMap;
use std::time::Duration;

use landscape_common::database::error::DbError;
use landscape_common::database::store::{Change, ConfigStore};
use landscape_common::database::validator::StoreValidator;
use landscape_common::service::ServiceConfigError;
use landscape_common::wan_link::{RuntimeWanLinkConfig, WanLinkConfig, WanLinkKind};
use sea_orm::DatabaseConnection;

use super::entity::{WanLinkConfigActiveModel, WanLinkConfigEntity, WanLinkConfigModel};
use crate::DBId;

/// Retries for a concurrent first-insert losing the `link_chain_id` race.
const CHAIN_ID_ALLOC_RETRIES: u32 = 8;

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

    /// Keeps `link_chain_id` stable across updates and allocates a free slot
    /// on insert, retrying on a concurrent-allocation unique-index clash.
    pub async fn upsert_preserving_chain_id(
        &self,
        mut config: WanLinkConfig,
    ) -> Result<Change<WanLinkConfig>, DbError> {
        match self.find_by_id(config.id).await? {
            Some(existing) => {
                config.link_chain_id = existing.link_chain_id;
                self.checked_upsert(config).await
            }
            None => {
                config.link_chain_id = 0;
                retry_on_chain_id_conflict(|| self.checked_upsert(config.clone())).await
            }
        }
    }
}

async fn retry_on_chain_id_conflict<T, F, Fut>(mut attempt: F) -> Result<T, DbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, DbError>>,
{
    let mut retries = 0;
    loop {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) if retries < CHAIN_ID_ALLOC_RETRIES && is_link_chain_id_conflict(&err) => {
                retries += 1;
                tokio::time::sleep(Duration::from_millis(5 * u64::from(retries))).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// True only for the `wan_links.link_chain_id` unique-index violation.
fn is_link_chain_id_conflict(err: &DbError) -> bool {
    let DbError::Database(db_err) = err else {
        return false;
    };
    let message = match db_err {
        sea_orm::DbErr::Exec(error) | sea_orm::DbErr::Query(error) => error.to_string(),
        _ => return false,
    };
    message.contains("wan_links.link_chain_id") || message.contains("idx_wan_links_link_chain_id")
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

        // Dynamic NAT ranges (None → runtime defaults) must not cover an
        // enabled static mapping's wan_port.
        if config.nat.enable {
            let nat = RuntimeWanLinkConfig::from_config(config).nat;
            let mappings =
                crate::static_nat_mapping_v4::repository::StaticNatMappingV4Repository::new(
                    self.db.clone(),
                )
                .list()
                .await
                .map_err(ServiceConfigError::internal)?
                .into_iter()
                .filter(|mapping| mapping.enable)
                .collect::<Vec<_>>();
            for (proto, range) in [(6u8, &nat.tcp_range), (17u8, &nat.udp_range)] {
                let proto_name = if proto == 6 { "TCP" } else { "UDP" };
                for mapping in &mappings {
                    if !mapping.l4_protocols.contains(&proto) {
                        continue;
                    }
                    for pair in &mapping.mapping_pair_ports {
                        if pair.wan_port >= range.start && pair.wan_port <= range.end {
                            return Err(ServiceConfigError::InvalidConfig {
                                reason: format!(
                                    "static NAT mapping {} wan_port {} ({proto_name}) overlaps this link's dynamic {proto_name} range {}..={}",
                                    mapping.id, pair.wan_port, range.start, range.end
                                ),
                            });
                        }
                    }
                }
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
    use landscape_common::config_service::static_nat::config::StaticMapPair;
    use landscape_common::config_service::static_nat::config4::{
        StaticNatMappingV4Config, StaticNatV4Target,
    };
    use landscape_common::database::error::DbError;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::service::ServiceConfigError;
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind, WanLinkNatConfig};
    use sea_orm::prelude::Uuid;
    use sea_orm::{ConnectionTrait, Database, DbErr};

    use super::is_link_chain_id_conflict;
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
            link_chain_id: 0,
            kind,
            v4: Default::default(),
            pd: Default::default(),
            nat: Default::default(),
            firewall: Default::default(),
            mss: Default::default(),
            update_at: 0.0,
        }
    }

    fn nat_link(
        id: Uuid,
        nat_enable: bool,
        tcp_range: Option<(u16, u16)>,
        udp_range: Option<(u16, u16)>,
    ) -> WanLinkConfig {
        let mut config = link(id, "eth0", WanLinkKind::Ethernet);
        config.nat = WanLinkNatConfig {
            enable: nat_enable,
            tcp_range: tcp_range.map(|(start, end)| start..end),
            udp_range: udp_range.map(|(start, end)| start..end),
            icmp_in_range: None,
        };
        config
    }

    async fn insert_enabled_mapping(
        provider: &LandscapeDBServiceProvider,
        wan_port: u16,
        proto: u8,
    ) {
        provider
            .static_nat_mapping_v4_store()
            .upsert(StaticNatMappingV4Config {
                id: Uuid::new_v4(),
                name: None,
                enable: true,
                remark: String::new(),
                wan_link_id: None,
                wan_iface_name: None,
                mapping_pair_ports: vec![StaticMapPair { wan_port, lan_port: 80 }],
                lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(
                    192, 168, 1, 100,
                ))),
                l4_protocols: vec![proto],
                update_at: 0.0,
            })
            .await
            .unwrap();
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

    #[tokio::test]
    async fn nat_link_rejected_when_range_covers_enabled_mapping() {
        let provider = setup().await;
        insert_enabled_mapping(&provider, 40000, 6).await;

        let result = provider
            .wan_link_store()
            .checked_upsert(nat_link(Uuid::new_v4(), true, Some((32768, 65535)), None))
            .await;
        let err = match result {
            Err(DbError::Validation(err)) => err.to_string(),
            other => panic!("expected validation error, got {other:?}"),
        };
        assert!(err.contains("static NAT mapping"), "{err}");
    }

    #[tokio::test]
    async fn nat_disabled_link_skips_mapping_overlap_check() {
        let provider = setup().await;
        insert_enabled_mapping(&provider, 40000, 6).await;

        provider
            .wan_link_store()
            .checked_upsert(nat_link(Uuid::new_v4(), false, Some((32768, 65535)), None))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nat_link_range_avoiding_mapping_allowed() {
        let provider = setup().await;
        insert_enabled_mapping(&provider, 40000, 6).await;

        provider
            .wan_link_store()
            .checked_upsert(nat_link(Uuid::new_v4(), true, Some((1024, 2048)), None))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nat_link_udp_range_overlap_rejected() {
        let provider = setup().await;
        insert_enabled_mapping(&provider, 15000, 17).await;

        let result = provider
            .wan_link_store()
            .checked_upsert(nat_link(Uuid::new_v4(), true, None, Some((10000, 20000))))
            .await;
        assert!(result.is_err(), "UDP mapping port must not fall in the link's udp range");
    }

    #[tokio::test]
    async fn inserts_allocate_distinct_chain_ids() {
        let provider = setup().await;
        let repo = provider.wan_link_store();

        let a = repo
            .upsert_preserving_chain_id(link(Uuid::new_v4(), "eth0", WanLinkKind::Ethernet))
            .await
            .unwrap()
            .new;
        let b = repo
            .upsert_preserving_chain_id(link(Uuid::new_v4(), "eth1", WanLinkKind::Ethernet))
            .await
            .unwrap()
            .new;

        assert_ne!(a.link_chain_id, 0);
        assert_ne!(b.link_chain_id, 0);
        assert_ne!(a.link_chain_id, b.link_chain_id);
    }

    #[tokio::test]
    async fn update_preserves_chain_id() {
        let provider = setup().await;
        let repo = provider.wan_link_store();

        let saved = repo
            .upsert_preserving_chain_id(link(Uuid::new_v4(), "eth0", WanLinkKind::Ethernet))
            .await
            .unwrap()
            .new;
        let original = saved.link_chain_id;
        assert_ne!(original, 0);

        let mut update = saved;
        update.link_chain_id = 0;
        let updated = repo.upsert_preserving_chain_id(update).await.unwrap().new;
        assert_eq!(updated.link_chain_id, original, "chain id is immutable after creation");
    }

    #[tokio::test]
    async fn concurrent_chain_id_allocation_converges() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain_alloc.db");

        let provider_a = LandscapeDBServiceProvider::file_test_db(&path).await;
        provider_a.iface_store().upsert(iface("eth0", IfaceZoneType::Wan)).await.unwrap();
        provider_a.iface_store().upsert(iface("eth1", IfaceZoneType::Wan)).await.unwrap();
        let provider_b = LandscapeDBServiceProvider::file_test_db(&path).await;

        let repo_a = provider_a.wan_link_store();
        let repo_b = provider_b.wan_link_store();
        let (a, b) = tokio::join!(
            repo_a.upsert_preserving_chain_id(link(Uuid::new_v4(), "eth0", WanLinkKind::Ethernet)),
            repo_b.upsert_preserving_chain_id(link(Uuid::new_v4(), "eth1", WanLinkKind::Ethernet)),
        );

        let a = a.unwrap().new;
        let b = b.unwrap().new;
        assert_ne!(a.link_chain_id, 0);
        assert_ne!(b.link_chain_id, 0);
        assert_ne!(a.link_chain_id, b.link_chain_id, "concurrent allocation must not collide");
    }

    async fn conflict_db() -> sea_orm::DatabaseConnection {
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

    async fn insert_raw_link(
        db: &sea_orm::DatabaseConnection,
        id: &str,
        chain: i64,
    ) -> Result<(), DbErr> {
        db.execute_unprepared(&format!(
            "INSERT INTO wan_links \
             (id, attach_iface_name, link_chain_id, kind, v4, pd, nat, firewall, mss) \
             VALUES ('{id}', 'wan0', {chain}, '{{}}', '{{}}', '{{}}', '{{}}', '{{}}', '{{}}')"
        ))
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn chain_id_unique_violation_is_recognized() {
        let db = conflict_db().await;
        insert_raw_link(&db, "00000000-0000-0000-0000-000000000001", 1).await.unwrap();
        let err = insert_raw_link(&db, "00000000-0000-0000-0000-000000000002", 1)
            .await
            .expect_err("duplicate link_chain_id must violate the unique index");
        assert!(is_link_chain_id_conflict(&DbError::from(err)));
    }

    #[tokio::test]
    async fn primary_key_violation_is_not_a_chain_id_conflict() {
        let db = conflict_db().await;
        insert_raw_link(&db, "00000000-0000-0000-0000-000000000001", 1).await.unwrap();
        let err = insert_raw_link(&db, "00000000-0000-0000-0000-000000000001", 2)
            .await
            .expect_err("duplicate primary key must fail");
        assert!(!is_link_chain_id_conflict(&DbError::from(err)));
    }

    #[test]
    fn non_unique_errors_are_not_chain_id_conflicts() {
        assert!(!is_link_chain_id_conflict(&DbError::Conflict));
        assert!(!is_link_chain_id_conflict(&DbError::Database(DbErr::Custom(
            "some other failure".to_string()
        ))));
    }
}
