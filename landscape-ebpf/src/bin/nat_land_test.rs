use landscape_common::args::RouteMode;
use landscape_common::iface::nat::NatConfig;
use landscape_ebpf::stages::nat::init_nat;
use std::net::Ipv4Addr;

// ip netns exec tpns cargo run --package landscape-ebpf --bin nat_land_test
// ip netns exec tpns nc -l -p 8080
// ip netns exec tpns nc 192.168.1.1 8080
#[tokio::main]
async fn main() {
    let ifindex: u32 = 96;
    let addr = Ipv4Addr::new(10, 200, 1, 1);
    landscape_ebpf::map_setting::add_ipv4_wan_ip(ifindex, addr, None, 24, None);

    let nat = init_nat(RouteMode::Tc, ifindex, true, &NatConfig::default())
        .expect("failed to start nat test");

    let _ = tokio::signal::ctrl_c().await;

    drop(nat);
}
