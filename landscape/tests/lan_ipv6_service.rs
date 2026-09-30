use std::sync::Arc;
use std::time::Duration;

use landscape::lan_service::lan_ipv6_service::LanIPv6ManagerService;
use landscape::sys_service::route::IpRouteService;
use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::hub::EventHub;
use landscape_common::event::route::RouteEvent;
use landscape_common::lan_service::lan_ipv6::LanIPv6ServiceConfigV2;
use landscape_common::lan_service::mac_binding::NoopMacBindingDataplane;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
use landscape_common::wan_service::ipv6_pd::prefix::IAPrefixMap;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

fn lan_ipv6_config(iface: &str, enable: bool) -> LanIPv6ServiceConfigV2 {
    // All LanIPv6ConfigV2 fields carry serde defaults; SLAAC with DHCPv6 off
    // keeps sockets/netlink out of the assertion paths that only observe
    // Disabled/Failed outcomes.
    let config = serde_json::from_value(serde_json::json!({})).unwrap();
    LanIPv6ServiceConfigV2 {
        iface_name: iface.to_string(),
        enable,
        config,
        update_at: 0.0,
    }
}

async fn lan_ipv6_service() -> LanIPv6ManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    provider
        .iface_store()
        .upsert(NetworkIfaceConfig::crate_bridge("lan0".to_string(), Some(IfaceZoneType::Lan)))
        .await
        .unwrap();
    let hub = EventHub::new();
    let ipv6_assign_sender = hub.ipv6_sender();
    let event_handle = hub.spawn();
    let (_route_tx, route_rx) = mpsc::channel::<RouteEvent>(8);
    let route_service = IpRouteService::new(
        route_rx,
        provider.flow_rule_store(),
        Arc::new(NoopRouteTableDataplane),
    );

    LanIPv6ManagerService::new(
        provider,
        event_handle.subscribe_iface(),
        event_handle.subscribe_device(),
        event_handle.subscribe_ipv6_prefix(),
        route_service,
        IAPrefixMap::default(),
        ipv6_assign_sender,
        Arc::new(NoopMacBindingDataplane),
        None,
    )
    .await
}

async fn wait_for_status(service: &LanIPv6ManagerService, iface: &str) -> ServiceStatus {
    for _ in 0..400 {
        if let Some(status) = service.get_all_status().await.get(iface) {
            return status.clone();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("service status for {iface} not observed in time");
}

#[tokio::test]
async fn handle_service_config_persists_and_tracks_service() {
    let service = lan_ipv6_service().await;

    // enable: false reports Disabled (clean stop), so the config persists
    // without starting RA/DHCPv6 servers.
    let saved = service.save_config(lan_ipv6_config("lan0", false)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("lan0".to_string()).await.unwrap().unwrap().iface_name, "lan0");
    assert_eq!(wait_for_status(&service, "lan0").await, ServiceStatus::Disabled);
}

#[tokio::test]
async fn failed_start_is_persisted_and_reported() {
    let service = lan_ipv6_service().await;

    // enable: true with an iface that does not exist in the test namespace:
    // the write persists (latest intent) and the starter reports Failed.
    let saved = service.save_config(lan_ipv6_config("lan0", true)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert!(service.find_by_id("lan0".to_string()).await.unwrap().is_some());
    assert_eq!(wait_for_status(&service, "lan0").await, ServiceStatus::Failed);
}

#[tokio::test]
async fn stale_save_config_conflicts_and_keeps_stored_config() {
    let service = lan_ipv6_service().await;

    let config = lan_ipv6_config("lan0", false);
    let saved = service.save_config(config.clone()).await.unwrap();

    let stale = service.save_config(config).await;
    assert!(matches!(
        stale.err(),
        Some(landscape_common::lan_service::lan_ipv6::LanIPv6Error::Internal(DbError::Conflict))
    ));

    let stored = service.find_by_id("lan0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = lan_ipv6_service().await;

    let missing = service.delete_and_stop_iface_service("lan0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.save_config(lan_ipv6_config("lan0", false)).await.unwrap();
    wait_for_status(&service, "lan0").await;

    let deleted = service.delete_and_stop_iface_service("lan0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("lan0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("lan0"));
}
