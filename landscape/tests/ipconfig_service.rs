use std::sync::Arc;
use std::time::Duration;

use landscape::sys_service::route::IpRouteService;
use landscape::wan_service::ipconfig_service::IfaceIpServiceManagerService;
use landscape_common::database::error::DbError;
use landscape_common::event::hub::EventHub;
use landscape_common::event::route::RouteEvent;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
use landscape_common::wan_service::addr_binding::NoopWanAddrBinding;
use landscape_common::wan_service::ip_config::{IfaceIpModelConfig, IfaceIpServiceConfig};
use landscape_common::wan_service::pppoe::NoopPppoeDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

fn ip_config(iface: &str, enable: bool) -> IfaceIpServiceConfig {
    IfaceIpServiceConfig {
        iface_name: iface.to_string(),
        enable,
        // Nothing: keeps netlink/DHCP/PPPoE paths out of the test.
        ip_model: IfaceIpModelConfig::Nothing,
        update_at: 0.0,
    }
}

async fn ip_service() -> IfaceIpServiceManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let hub = EventHub::new();
    let event_handle = hub.spawn();
    let (_route_tx, route_rx) = mpsc::channel::<RouteEvent>(8);
    let route_service = IpRouteService::new(
        route_rx,
        provider.flow_rule_store(),
        Arc::new(NoopRouteTableDataplane),
    );

    IfaceIpServiceManagerService::new(
        route_service,
        Arc::new(NoopWanAddrBinding),
        Arc::new(NoopPppoeDataplane),
        provider,
        event_handle.subscribe_iface(),
    )
    .await
}

async fn wait_for_status(service: &IfaceIpServiceManagerService, iface: &str) -> ServiceStatus {
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
    let service = ip_service().await;

    // enable: false reports Disabled (clean stop), so the config persists
    // without touching netlink.
    let saved = service.handle_service_config(ip_config("wan0", false)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("wan0".to_string()).await.unwrap().unwrap().iface_name, "wan0");
    assert_eq!(wait_for_status(&service, "wan0").await, ServiceStatus::Disabled);
}

#[tokio::test]
async fn missing_iface_fails_start_and_rejects_persist() {
    let service = ip_service().await;

    // enable: true with an iface that does not exist in the test namespace:
    // the starter reports Failed, persist-after-verify rejects the write.
    let result = service.handle_service_config(ip_config("wan0", true)).await;

    assert!(matches!(result, Err(DbError::ServiceStart(_))));
    assert!(service.find_by_id("wan0".to_string()).await.unwrap().is_none());
}

#[tokio::test]
async fn stale_handle_service_config_conflicts_and_keeps_stored_config() {
    let service = ip_service().await;

    let config = ip_config("wan0", false);
    let saved = service.handle_service_config(config.clone()).await.unwrap();

    let stale = service.handle_service_config(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));

    let stored = service.find_by_id("wan0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = ip_service().await;

    let missing = service.delete_and_stop_iface_service("wan0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.handle_service_config(ip_config("wan0", false)).await.unwrap();
    wait_for_status(&service, "wan0").await;

    let deleted = service.delete_and_stop_iface_service("wan0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("wan0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("wan0"));
}
