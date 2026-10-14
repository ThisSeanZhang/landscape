use landscape_common::wan_service::nat::config::NatConfig;
use std::net::Ipv4Addr;

// ip netns exec tpns cargo run --package landscape-ebpf --bin nat_land_test
// ip netns exec tpns nc -l -p 8080
// ip netns exec tpns nc 192.168.1.1 8080
#[tokio::main]
async fn main() {
    landscape_common::init_tracing!();
    landscape_ebpf::setting_libbpf_log();

    let rt = std::sync::Arc::new(
        landscape_ebpf::runtime::EbpfRuntime::init("nat_land_test", None)
            .expect("failed to init ebpf runtime"),
    );
    let ifindex: u32 = 96;
    let addr = Ipv4Addr::new(10, 200, 1, 1);
    landscape_ebpf::maps::wan::add_ipv4_wan_ip(rt.paths(), ifindex, addr, None, 24, None);

    let nat4 = landscape_ebpf::stages::nat4::attach_nat4(&rt, ifindex, true, &NatConfig::default())
        .expect("failed to start nat4 test");
    let nat6 = landscape_ebpf::stages::nat6::attach_nat6(&rt, ifindex, true)
        .expect("failed to start nat6 test");

    let _ = tokio::signal::ctrl_c().await;

    drop(nat4);
    drop(nat6);
}
