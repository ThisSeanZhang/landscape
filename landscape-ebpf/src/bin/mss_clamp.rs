// cargo run --package landscape-ebpf --bin mss_clamp
// cargo build --package landscape-ebpf --bin mss_clamp --target aarch64-unknown-linux-gnu
#[tokio::main]
pub async fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let rt = std::sync::Arc::new(
        landscape_ebpf::runtime::EbpfRuntime::init("mss_clamp", None)
            .expect("failed to init ebpf runtime"),
    );
    let ifindex = 2;
    println!("Starting mss clamp on ifindex: {:?}", ifindex);
    let dp = landscape_ebpf::chain::wan_link::WanLinkDataplane::new(
        rt.backbone().clone(),
        rt.xdp_attach().clone(),
        1,
        Some(ifindex),
        true,
    )
    .unwrap();
    let mss_clamp = landscape_ebpf::stages::mss::init_mss(&dp, 1492, true).unwrap();

    let _ = tokio::signal::ctrl_c().await;

    drop(mss_clamp);
    dp.close();
}
