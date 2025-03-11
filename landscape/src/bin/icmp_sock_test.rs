use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use landscape::{icmp::v6::icmp_ra_server, iface::get_iface_by_name};
use landscape_common::{
    global_const::{LDIAPrefix, LD_PD_WATCHES},
    service::{DefaultWatchServiceStatus, ServiceStatus},
};
use tracing::Level;

#[derive(Parser, Debug, Clone)]
pub struct Args {
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

    LD_PD_WATCHES
        .insert_or_replace(
            &args.iface_name,
            LDIAPrefix {
                preferred_lifetime: 60 * 60 * 24 * 1,
                valid_lifetime: 60 * 60 * 24 * 2,
                prefix_len: 48,
                prefix_ip: "fd00:abcd:1234::".parse().unwrap(),
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

    tokio::spawn(async move {
        if let Some(iface) = get_iface_by_name(&args.iface_name).await {
            if let Some(mac) = iface.mac {
                icmp_ra_server(64, 1, mac, iface.name, status).await.unwrap();
            }
        }
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
    }

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
