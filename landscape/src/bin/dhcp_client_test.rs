use landscape::{get_iface_by_name, sys_service::route::IpRouteService};
use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
    service::{ServiceHandle, ServiceStatus},
};
use landscape_ebpf::runtime::EbpfRuntime;

use clap::Parser;
use std::sync::Arc;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "ens4")]
    pub iface_name: String,
}

/// cargo run --package landscape --bin dhcp_client_test
#[tokio::main]
async fn main() {
    landscape_common::init_tracing!();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);

    let service_status = ServiceHandle::new();

    let status = service_status.clone();

    let rt = Arc::new(EbpfRuntime::init("dhcp_client_test", None).expect("init ebpf maps"));
    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.iface_name).await
            && let Some(mac) = iface.mac
        {
            let config = landscape::wan_service::dhcpv4_client::DhcpV4ClientServiceRuntimeConfig {
                link_id: uuid::Uuid::new_v4(),
                ifindex: iface.index,
                iface_name: iface.name,
                mac_addr: mac,
                client_port: LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
                hostname: "TEST-PC".to_string(),
                default_router: false,
            };
            let services = landscape::wan_service::dhcpv4_client::DhcpV4ClientServices {
                route_service: IpRouteService::new(rt.clone().route_table()),
                addr_binding: rt.wan_addr_binding(),
                session: None,
                runtime: Arc::new(arc_swap::ArcSwap::from_pointee(
                    landscape_common::wan_link::V4Runtime::Idle,
                )),
            };
            landscape::wan_service::dhcpv4_client::run(config, services, status).await;
        }
    });

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl+c");

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
