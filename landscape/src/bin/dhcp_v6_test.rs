use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use clap::Parser;
use landscape::{dhcp_client::v6::dhcp_v6_pd_client, macaddr::MacAddr};
use landscape_common::{
    service::{DefaultWatchServiceStatus, ServiceStatus},
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use tracing::Level;

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
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

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
    let service_status = DefaultWatchServiceStatus::new();

    let status = service_status.clone();
    tokio::spawn(async move {
        dhcp_v6_pd_client(args.iface_name, mac_addr, LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT, status)
            .await;
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
    }

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
