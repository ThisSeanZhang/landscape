use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use landscape::{
    dhcp_client::v6::dhcp_v6_pd_client, icmp::v6::icmp_ra_server, iface::get_iface_by_name,
};
use landscape_common::{config::ra::IPV6RAConfig, net::MacAddr};
use landscape_common::{
    service::{DefaultWatchServiceStatus, ServiceStatus},
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};

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
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let Some(mac_addr) = MacAddr::from_str(&args.mac) else {
        tracing::error!("mac parse error, mac is: {:?}", args.mac);
        return;
    };

    let dhcp_service_status = DefaultWatchServiceStatus::new();

    let config = IPV6RAConfig::new(args.dhcp_client_iface.clone());

    let status = dhcp_service_status.clone();
    tokio::spawn(async move {
        dhcp_v6_pd_client(
            args.dhcp_client_iface,
            mac_addr,
            LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
            status,
        )
        .await;
    });
    let icmp_service_status = DefaultWatchServiceStatus::new();

    let status = icmp_service_status.clone();
    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.icmp_ra_iface).await {
            if let Some(mac) = iface.mac {
                icmp_ra_server(config, mac, iface.name, status).await.unwrap();
            }
        }
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
    }

    dhcp_service_status.just_change_status(ServiceStatus::Stopping);
    icmp_service_status.just_change_status(ServiceStatus::Stopping);

    icmp_service_status.wait_stop().await;
    dhcp_service_status.wait_stop().await;
}
