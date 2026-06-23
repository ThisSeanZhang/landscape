use std::sync::Arc;

use clap::Parser;
use landscape::ipv6::prefix::IPv6PrefixRuntime;
use landscape::{icmp::v6::icmp_ra_server, iface::get_iface_by_name};
use landscape_common::{
    event::hub::IPv6AssignEventSender,
    ipv6::ra::RouterFlags,
    lan_services::ipv6_ra::IPv6NAInfo,
    service::{ServiceStatus, WatchService},
};
use tokio::sync::{watch, RwLock};
use tracing::Level;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "ens5")]
    pub iface_name: String,
}

// ping6 -I ens5 ff02::1
// cargo run --package landscape --bin icmp_sock_test
// rdisc6 ens6
#[tokio::main]
async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);

    let service_status = WatchService::new();
    let status = service_status.clone();

    let runtime = IPv6PrefixRuntime {
        static_info: vec![],
        pd_info: std::collections::HashMap::new(),
        pd_delegation_static: vec![],
        pd_delegation_dynamic: vec![],
        relative_boot_time: tokio::time::Instant::now(),
    };
    let (_change_tx, change_rx) = watch::channel(());

    let assigned_ips = Arc::new(RwLock::new(IPv6NAInfo::init()));
    let ra_flag = RouterFlags::from(0u8);
    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.iface_name).await {
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

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
