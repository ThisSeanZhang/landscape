use landscape_ebpf::nat::{init_nat, NatConfig};
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::oneshot, time::sleep};

// ip netns exec tpns cargo run --package landscape-ebpf --bin nat_land_test
// ip netns exec tpns nc -l -p 8080
// ip netns exec tpns nc 192.168.1.1 8080
#[tokio::main]
async fn main() {
    let ifindex: i32 = 96;
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let addr = Ipv4Addr::new(10, 200, 1, 1);
    landscape_ebpf::map_setting::add_wan_ip(ifindex as u32, addr);
    std::thread::spawn(move || {
        init_nat(ifindex, true, rx, NatConfig::default());
        let _ = other_tx.send(());
    });

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0)).await;
    }

    let _ = tx.send(());
    let _ = other_rx.await;
}
