use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{sync::oneshot, time::sleep};

#[tokio::main]
pub async fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let ifindex = 9;
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    std::thread::spawn(move || {
        println!("启动 packet_mark 在 ifindex: {:?}", ifindex);
        landscape_ebpf::packet_mark::init_packet_mark(ifindex, true, rx);
        println!("向外部线程发送解除阻塞信号");
        other_tx.send(());
    });

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0)).await;
    }

    let _ = tx.send(());
    let _ = other_rx.await;
}
