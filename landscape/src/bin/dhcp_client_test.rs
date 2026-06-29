use landscape::{
    get_iface_by_name, sys_service::route::IpRouteService,
    wan_service::dhcpv4_client::v4::dhcp_v4_client,
};
use landscape_common::{
    service::{ServiceStatus, WatchService},
    LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
};

use clap::Parser;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

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

    let db_store_provider = LandscapeDBServiceProvider::mem_test_db().await;
    let flow_repo = db_store_provider.flow_rule_store();

    let service_status = WatchService::new();

    let status = service_status.clone();

    let (_, route_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.iface_name).await {
            if let Some(mac) = iface.mac {
                dhcp_v4_client(
                    iface.index,
                    iface.name,
                    mac,
                    LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
                    status,
                    "TEST-PC".to_string(),
                    false,
                    IpRouteService::new(route_rx, flow_repo),
                )
                .await;
            }
        }
    });

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl+c");

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
