use std::sync::Arc;
use std::time::Duration;

use landscape::sys_service::route::IpRouteService;
use landscape::wan_service::pppd_service::PPPDServiceConfigManagerService;
use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::route::RouteEvent;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
use landscape_common::wan_service::addr_binding::NoopWanAddrBinding;
use landscape_common::wan_service::pppd::{PPPDConfig, PPPDServiceConfig};
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

fn pppd_config(iface: &str, enable: bool) -> PPPDServiceConfig {
    PPPDServiceConfig {
        attach_iface_name: "wan9".to_string(),
        iface_name: iface.to_string(),
        enable,
        pppd_config: PPPDConfig {
            default_route: true,
            peer_id: "test".to_string(),
            password: "test".to_string(),
            ac: None,
            plugin: Default::default(),
        },
        update_at: 0.0,
    }
}

async fn seed_wan_iface(provider: &LandscapeDBServiceProvider, name: &str) {
    provider
        .iface_store()
        .upsert(NetworkIfaceConfig::crate_bridge(name.to_string(), Some(IfaceZoneType::Wan)))
        .await
        .unwrap();
}

async fn pppd_manager() -> PPPDServiceConfigManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    seed_wan_iface(&provider, "wan9").await;
    let (_route_tx, route_rx) = mpsc::channel::<RouteEvent>(8);
    let route_service = IpRouteService::new(
        route_rx,
        provider.flow_rule_store(),
        Arc::new(NoopRouteTableDataplane),
    );

    PPPDServiceConfigManagerService::new(provider, route_service, Arc::new(NoopWanAddrBinding))
        .await
}

async fn wait_for_status(service: &PPPDServiceConfigManagerService, iface: &str) -> ServiceStatus {
    for _ in 0..400 {
        if let Some(status) = service.get_all_status().await.get(iface) {
            return status.clone();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("service status for {iface} not observed in time");
}

#[tokio::test]
async fn handle_service_config_persists_disabled_service() {
    let service = pppd_manager().await;

    // enable: false reports Disabled (clean stop); the config persists without
    // touching netlink or /etc/ppp.
    let saved = service.handle_service_config(pppd_config("ppp0", false)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("ppp0".to_string()).await.unwrap().unwrap().iface_name, "ppp0");
    assert_eq!(wait_for_status(&service, "ppp0").await, ServiceStatus::Disabled);
}

#[tokio::test]
async fn failed_start_is_persisted_and_reported() {
    let service = pppd_manager().await;

    // enable: true with an attach iface that does not exist in the test
    // namespace: the write persists (latest intent) and the starter reports
    // Failed.
    let saved = service.handle_service_config(pppd_config("ppp0", true)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert!(service.find_by_id("ppp0".to_string()).await.unwrap().is_some());
    assert_eq!(wait_for_status(&service, "ppp0").await, ServiceStatus::Failed);
}

#[tokio::test]
async fn stale_handle_service_config_conflicts_and_keeps_stored_config() {
    let service = pppd_manager().await;

    let config = pppd_config("ppp0", false);
    let saved = service.handle_service_config(config.clone()).await.unwrap();

    // Re-submitting the stale (pre-save) version must conflict.
    let stale = service.handle_service_config(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));

    let stored = service.find_by_id("ppp0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = pppd_manager().await;

    let missing = service.delete_and_stop_pppd("ppp0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.handle_service_config(pppd_config("ppp0", false)).await.unwrap();
    wait_for_status(&service, "ppp0").await;

    let deleted = service.delete_and_stop_pppd("ppp0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("ppp0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("ppp0"));
}
