// cargo run --package landscape-ebpf --bin mss_clamp
// cargo build --package landscape-ebpf --bin mss_clamp --target aarch64-unknown-linux-gnu
#[tokio::main]
pub async fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let ifindex = 2;
    println!("Starting mss clamp on ifindex: {:?}", ifindex);
    let mss_clamp = landscape_ebpf::stages::mss::init_mss(ifindex, 1492, true).unwrap();

    let _ = tokio::signal::ctrl_c().await;

    drop(mss_clamp);
}
