use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use clap::Parser;
use landscape::sys_service::route::IpRouteService;
use landscape::{get_iface_by_name, wan_service::ipv6pd_client::v6::dhcp_v6_pd_client};
use landscape_common::{
    event::hub::IAPrefixEventSender, sys_service::route_service::RouteTargetInfo,
    wan_service::ipv6_pd::IAPrefixMap,
};
use landscape_common::{
    service::{ServiceStatus, WatchService},
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_ebpf::runtime::EbpfRuntime;
use tokio::sync::mpsc;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "ens6")]
    pub iface_name: String,

    #[arg(short, long, default_value = "00:a0:98:39:32:f0")]
    pub mac: String,
}

// cargo run --package landscape --bin dhcp_v6_test
// dhclient -6 -d -v -1 -P -lf /dev/null ens6
#[tokio::main]
async fn main() {
    landscape_common::init_tracing!();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);
    let iface =
        get_iface_by_name(&args.iface_name).await.expect("could nt find iface by iface name");

    let Some(mac_addr) = iface.mac else {
        tracing::error!("mac parse error, mac is: {:?}", args.mac);
        return;
    };

    let service_status = WatchService::new();
    let db_store_provider = LandscapeDBServiceProvider::mem_test_db().await;
    let flow_repo = db_store_provider.flow_rule_store();
    let (_, route_rx) = mpsc::channel(1);
    let rt = Arc::new(EbpfRuntime::init("dhcp_v6_test", None).expect("init ebpf maps"));
    let ip_route = IpRouteService::new(route_rx, flow_repo, rt.clone().route_table());
    let status = service_status.clone();
    let prefix_map = IAPrefixMap::new();
    let (prefix_tx, _prefix_rx) = mpsc::channel(1);
    let prefix_sender = IAPrefixEventSender::new(prefix_tx);
    drop(_prefix_rx); // test binary: no event consumer, events are silently discarded
    tokio::spawn(async move {
        let route_info = RouteTargetInfo {
            ifindex: 6,
            weight: 1,
            mac: iface.mac,
            is_docker: false,
            iface_name: "test".to_string(),
            iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            default_route: true,
            gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        dhcp_v6_pd_client(
            args.iface_name,
            iface.index,
            iface.mac,
            mac_addr,
            60,
            LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
            status,
            route_info,
            ip_route,
            rt.wan_addr_binding(),
            prefix_map,
            std::sync::Arc::new(2),
            prefix_sender,
        )
        .await;
    });

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl+c");

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
