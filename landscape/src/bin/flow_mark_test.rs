use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use landscape::iface::get_iface_by_name;
use tokio::{sync::oneshot, time::sleep};

use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[arg(short, long, default_value = "ens3")]
    pub iface_name: String,
}

// cargo run --package landscape --bin flow_mark_test
#[tokio::main]
pub async fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let args = Args::parse();
    tracing::info!("using args is: {:#?}", args);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    if let Some(iface) = get_iface_by_name(&args.iface_name).await {
        std::thread::spawn(move || {
            println!("启动 packet_mark 在 ifindex: {:?}", iface.index);
            landscape_ebpf::flow::verdict::attach_verdict_flow(
                iface.index as i32,
                iface.mac.is_some(),
                rx,
            )
            .unwrap();
            println!("向外部线程发送解除阻塞信号");
            let _ = other_tx.send(());
        });
    }

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0)).await;
    }

    let _ = tx.send(());
    let _ = other_rx.await;
}
