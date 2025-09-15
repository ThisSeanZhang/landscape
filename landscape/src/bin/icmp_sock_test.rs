use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use landscape::{icmp::v6::icmp_ra_server, iface::get_iface_by_name};
use landscape_common::{
    config::ra::IPV6RAConfig,
    ipv6_pd::{IAPrefixMap, LDIAPrefix},
    route::LanRouteInfo,
    service::{DefaultWatchServiceStatus, ServiceStatus},
};
use tracing::Level;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "veth0")]
    pub depend_iface: String,

    #[arg(short, long, default_value = "ens5")]
    pub iface_name: String,
}

// ping6 -I ens5 ff02::1
// cargo run --package landscape --bin icmp_sock_test
// rdisc6 ens6
// ip6tables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source fd8d:c6a4:708f:0:2a0:98ff:fe08:5909
#[tokio::main]
async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);

    let prefix_map = IAPrefixMap::new();
    prefix_map
        .insert_or_replace(
            &args.depend_iface,
            LDIAPrefix {
                preferred_lifetime: 60 * 60 * 24 * 1,
                valid_lifetime: 60 * 60 * 24 * 2,
                prefix_len: 48,
                prefix_ip: "fd00:abcd:1234::".parse().unwrap(),
                last_update_time: 0.0,
            },
        )
        .await;
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let service_status = DefaultWatchServiceStatus::new();

    let status = service_status.clone();

    let (_, ip_route) = landscape::route::test_used_ip_route().await;
    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.iface_name).await {
            if let Some(mac) = iface.mac {
                let config = IPV6RAConfig::new(args.depend_iface.clone());
                let lan_info = LanRouteInfo {
                    ifindex: iface.index,
                    iface_name: iface.name.clone(),
                    iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    mac: Some(mac.clone()),
                    prefix: 128,
                };
                icmp_ra_server(config, mac, iface.name, status, lan_info, ip_route, prefix_map)
                    .await
                    .unwrap();
            }
        }
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
    }

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
