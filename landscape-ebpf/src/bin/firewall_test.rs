use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{sync::oneshot, time::sleep};
use tracing::Level;

// cargo run --package landscape-ebpf --bin firewall_test
#[tokio::main]
pub async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt().with_max_level(Level::DEBUG).with_writer(non_blocking).init();
    landscape_ebpf::setting_libbpf_log();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let ifindex = 10;
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    std::thread::spawn(move || {
        println!("启动 firewall 在 ifindex: {:?}", ifindex);
        if let Err(e) = landscape_ebpf::firewall::new_firewall(ifindex, true, rx) {
            tracing::debug!("error: {e:?}");
        }
        println!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
    });

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0)).await;
    }

    let _ = tx.send(());
    let _ = other_rx.await;
}
