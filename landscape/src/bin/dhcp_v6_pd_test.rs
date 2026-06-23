use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use clap::Parser;
use landscape::ipv6::prefix::IPv6PrefixRuntime;
use landscape::{
    dhcp_client::v6::dhcp_v6_pd_client, icmp::v6::icmp_ra_server, iface::get_iface_by_name,
};
use landscape_common::{
    event::hub::IPv6AssignEventSender, ipv6::ra::RouterFlags, ipv6_pd::IAPrefixMap,
    lan_services::ipv6_ra::IPv6NAInfo, net::MacAddr, route::RouteTargetInfo,
};
use landscape_common::{
    service::{ServiceStatus, WatchService},
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use tokio::sync::{watch, RwLock};

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "ens6")]
    pub dhcp_client_iface: String,

    #[arg(short, long, default_value = "00:a0:98:39:32:f0")]
    pub mac: String,

    #[arg(short, long, default_value = "veth0")]
    pub icmp_ra_iface: String,
}

// cargo run --package landscape --bin dhcp_v6_pd_test
#[tokio::main]
async fn main() {
    landscape_common::init_tracing!();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);
    let Some(mac_addr) = MacAddr::from_str(&args.mac) else {
        tracing::error!("mac parse error, mac is: {:?}", args.mac);
        return;
    };

    let dhcp_service_status = WatchService::new();

    let (_, ip_route) = landscape::route::test_used_ip_route().await;
    let status = dhcp_service_status.clone();
    let ip_route_service = ip_route.clone();

    let prefix_map = IAPrefixMap::new();
    let prefix_map_clone = prefix_map.clone();
    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.dhcp_client_iface).await {
            let route_info = RouteTargetInfo {
                ifindex: 6,
                weight: 1,
                mac: iface.mac.clone(),
                is_docker: false,
                iface_name: "test".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                default_route: true,
                gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            dhcp_v6_pd_client(
                args.dhcp_client_iface,
                iface.index,
                iface.mac,
                mac_addr,
                LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
                status,
                route_info,
                ip_route_service,
                prefix_map_clone,
                Arc::new(2),
            )
            .await;
        }
    });
    let icmp_service_status = WatchService::new();
    let status = icmp_service_status.clone();
    let assigned_ips = Arc::new(RwLock::new(IPv6NAInfo::init()));

    let runtime = IPv6PrefixRuntime {
        static_info: vec![],
        pd_info: std::collections::HashMap::new(),
        pd_delegation_static: vec![],
        pd_delegation_dynamic: vec![],
        relative_boot_time: tokio::time::Instant::now(),
    };
    let (_change_tx, change_rx) = watch::channel(());
    let ra_flag = RouterFlags::from(0u8);

    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.icmp_ra_iface).await {
            if let Some(mac) = iface.mac {
                let (ipv6_tx, _) = tokio::sync::mpsc::channel(32);
                let ipv6_assign_sender = IPv6AssignEventSender::new(ipv6_tx);
                icmp_ra_server(
                    300,
                    ra_flag,
                    mac,
                    iface.name,
                    status,
                    &runtime,
                    change_rx,
                    assigned_ips,
                    true,
                    None,
                    None,
                    iface.index,
                    ipv6_assign_sender,
                )
                .await
                .unwrap();
            }
        }
    });

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl+c");

    dhcp_service_status.just_change_status(ServiceStatus::Stopping);
    icmp_service_status.just_change_status(ServiceStatus::Stopping);

    icmp_service_status.wait_stop().await;
    dhcp_service_status.wait_stop().await;
}
