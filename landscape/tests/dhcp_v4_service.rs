use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use landscape::lan_service::lan_dhcp4_service::DHCPv4ServerManagerService;
use landscape::sys_service::route::IpRouteService;
use landscape_common::config::DnsRuntimeConfig;
use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::hub::EventHub;
use landscape_common::event::route::RouteEvent;
use landscape_common::lan_service::lan_dhcpv4::config::DHCPv4ServiceConfig;
use landscape_common::lan_service::mac_binding::NoopMacBindingDataplane;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

fn dhcp_config(iface: &str, enable: bool) -> DHCPv4ServiceConfig {
    DHCPv4ServiceConfig {
        iface_name: iface.to_string(),
        enable,
        config: Default::default(),
        update_at: 0.0,
    }
}

async fn seed_lan_iface(provider: &LandscapeDBServiceProvider, name: &str) {
    provider
        .iface_store()
        .upsert(NetworkIfaceConfig::crate_bridge(name.to_string(), Some(IfaceZoneType::Lan)))
        .await
        .unwrap();
}

async fn dhcp_service() -> DHCPv4ServerManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    seed_lan_iface(&provider, "lan0").await;
    let hub = EventHub::new();
    let ipv4_assign_sender = hub.ipv4_sender();
    let event_handle = hub.spawn();
    let (_route_tx, route_rx) = mpsc::channel::<RouteEvent>(8);
    let route_service = IpRouteService::new(
        route_rx,
        provider.flow_rule_store(),
        Arc::new(NoopRouteTableDataplane),
    );

    let dns_runtime_config = DnsRuntimeConfig {
        cache_capacity: 1024,
        cache_ttl: 600,
        negative_cache_ttl: 60,
        doh_listen_port: 8053,
        doh_http_endpoint: "/dns-query".to_string(),
    };

    DHCPv4ServerManagerService::new(
        route_service,
        provider,
        landscape::cert::SharedSniResolver::new(),
        dns_runtime_config,
        Arc::new(ArcSwap::from_pointee(LanHostnameConfig::default())),
        event_handle.subscribe_iface(),
        ipv4_assign_sender,
        event_handle.subscribe_device(),
        Arc::new(NoopMacBindingDataplane),
    )
    .await
}

async fn wait_for_status(service: &DHCPv4ServerManagerService, iface: &str) -> ServiceStatus {
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
    let service = dhcp_service().await;

    // enable: false reports Disabled (clean stop) and still cleans the LAN
    // route, so the config persists without binding sockets.
    let saved = service.handle_service_config(dhcp_config("lan0", false)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("lan0".to_string()).await.unwrap().unwrap().iface_name, "lan0");
    assert_eq!(wait_for_status(&service, "lan0").await, ServiceStatus::Disabled);
}

#[tokio::test]
async fn failed_start_is_persisted_and_reported() {
    let service = dhcp_service().await;

    // enable: true with an iface that does not exist in the test namespace:
    // the write persists (latest intent) and the starter reports Failed.
    let saved = service.handle_service_config(dhcp_config("lan0", true)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert!(service.find_by_id("lan0".to_string()).await.unwrap().is_some());
    assert_eq!(wait_for_status(&service, "lan0").await, ServiceStatus::Failed);
}

#[tokio::test]
async fn stale_handle_service_config_conflicts_and_keeps_stored_config() {
    let service = dhcp_service().await;

    let config = dhcp_config("lan0", false);
    let saved = service.handle_service_config(config.clone()).await.unwrap();

    let stale = service.handle_service_config(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));

    let stored = service.find_by_id("lan0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = dhcp_service().await;

    let missing = service.delete_and_stop_service("lan0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.handle_service_config(dhcp_config("lan0", false)).await.unwrap();
    wait_for_status(&service, "lan0").await;

    let deleted = service.delete_and_stop_service("lan0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("lan0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("lan0"));
}
