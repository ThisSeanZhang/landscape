use landscape::metric::MetricData;
use landscape_common::LANDSCAPE_METRIC_DIR_NAME;
use landscape_ebpf::metric::new_metric;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::oneshot;

// cargo run --package landscape-ebpf --bin event_metric_loop
#[tokio::main]
async fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let metric_path = PathBuf::from("/root/.landscape-router").join(LANDSCAPE_METRIC_DIR_NAME);

    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    let metric_service = MetricData::new(
        metric_path,
        landscape_common::config::MetricRuntimeConfig {
            conn_retention_days: landscape_common::DEFAULT_CONN_METRIC_RETENTION_DAYS,
            conn_retention_hour_days: landscape_common::DEFAULT_CONN_METRIC_RETENTION_DAYS_1H,
            conn_retention_day_days: landscape_common::DEFAULT_CONN_METRIC_RETENTION_DAYS_1D,
            dns_retention_days: landscape_common::DEFAULT_DNS_METRIC_RETENTION_DAYS,
            batch_size: landscape_common::DEFAULT_METRIC_BATCH_SIZE,
            flush_interval_secs: landscape_common::DEFAULT_METRIC_FLUSH_INTERVAL_SECS,
            max_memory: 128,
            max_threads: 1,
        },
    )
    .await;
    let metric_service_clone = metric_service.clone();
    std::thread::spawn(move || {
        new_metric(rx, metric_service_clone.connect_metric.get_msg_channel());
        let _ = other_tx.send(());
    });

    while running.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::new(1, 0)).await;
        println!("data: {:?}", metric_service.connect_metric.connect_infos().await);
    }

    let _ = tx.send(());
    let _ = other_rx.await;
}
