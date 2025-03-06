use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use landscape::{dhcp_client::v6::dhcp_v6_pd_client, macaddr::MacAddr};
use landscape_common::{
    service::{DefaultWatchServiceStatus, ServiceStatus},
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use tracing::Level;

// cargo run --package landscape --bin dhcp_v6_test
// dhclient -6 -d -v -1 -P -lf /dev/null ens6
#[tokio::main]
async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let mac_addr = MacAddr::new(00, 0xa0, 0x98, 0x39, 0x32, 0xf0);
    let service_status = DefaultWatchServiceStatus::new();

    let status = service_status.clone();
    tokio::spawn(async move {
        dhcp_v6_pd_client("ens6".into(), mac_addr, LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT, status)
            .await;
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
    }

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
