use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use landscape::icmp::v6::icmp_ra_server;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use tracing::Level;

// ping6 -I ens5 ff02::1
// cargo run --package landscape --bin icmp_sock_test
// rdisc6 ens6
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

    let service_status = DefaultWatchServiceStatus::new();

    let status = service_status.clone();

    tokio::spawn(async move {
        icmp_ra_server("ens5".into(), status).await.unwrap();
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
    }

    service_status.just_change_status(ServiceStatus::Stopping);

    service_status.wait_stop().await;
}
