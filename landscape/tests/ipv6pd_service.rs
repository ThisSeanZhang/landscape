use std::sync::Arc;
use std::time::Duration;

use landscape::sys_service::route::IpRouteService;
use landscape::wan_service::ipv6pd_service::DHCPv6ClientManagerService;
use landscape_common::database::error::DbError;
use landscape_common::event::hub::EventHub;
use landscape_common::event::route::RouteEvent;
use landscape_common::net::MacAddr;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
use landscape_common::wan_service::addr_binding::NoopWanAddrBinding;
use landscape_common::wan_service::ipv6_pd::config::{IPV6PDConfig, IPV6PDServiceConfig};
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

fn pd_config(iface: &str) -> IPV6PDServiceConfig {
    IPV6PDServiceConfig {
        iface_name: iface.to_string(),
        // Disabled: keeps the PD client's netlink path out of the test.
        enable: false,
        config: IPV6PDConfig {
            mac: MacAddr::from([0, 1, 2, 3, 4, 5]),
            expected_pd_len: 60,
        },
        update_at: 0.0,
    }
}

async fn ipv6pd_service() -> DHCPv6ClientManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let (_route_tx, route_rx) = mpsc::channel::<RouteEvent>(8);
    let route_service = IpRouteService::new(
        route_rx,
        provider.flow_rule_store(),
        Arc::new(NoopRouteTableDataplane),
    );

    let hub = EventHub::new();
    let prefix_sender = hub.ipv6_prefix_sender();
    let event_handle = hub.spawn();

    DHCPv6ClientManagerService::new(
        provider,
        event_handle.subscribe_iface(),
        route_service,
        Arc::new(NoopWanAddrBinding),
        IAPrefixMap::new(),
        prefix_sender,
        Arc::new(0u64),
    )
    .await
    .unwrap()
}

async fn wait_for_status(service: &DHCPv6ClientManagerService, iface: &str) {
    for _ in 0..400 {
        if service.get_all_status().await.contains_key(iface) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("service status for {iface} not observed in time");
}

#[tokio::test]
async fn handle_service_config_persists_and_tracks_service() {
    let service = ipv6pd_service().await;

    let saved = service.handle_service_config(pd_config("wan0")).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("wan0".to_string()).await.unwrap().unwrap().iface_name, "wan0");
    wait_for_status(&service, "wan0").await;
}

#[tokio::test]
async fn stale_handle_service_config_conflicts_and_keeps_stored_config() {
    let service = ipv6pd_service().await;

    let config = pd_config("wan0");
    let saved = service.handle_service_config(config.clone()).await.unwrap();

    // Re-submitting the stale (pre-save) version must conflict; the running
    // service is rolled back to the stored config by the controller.
    let stale = service.handle_service_config(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));

    let stored = service.find_by_id("wan0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = ipv6pd_service().await;

    let missing = service.delete_and_stop_service("wan0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.handle_service_config(pd_config("wan0")).await.unwrap();
    wait_for_status(&service, "wan0").await;

    let deleted = service.delete_and_stop_service("wan0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("wan0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("wan0"));
}
