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
    let link_chain_id: u16 = 1;
    let addr = Ipv4Addr::new(10, 200, 1, 1);
    // Still consumed by the route side (is_current checks).
    landscape_ebpf::maps::wan::add_ipv4_wan_ip(rt.paths(), ifindex, addr, None, 24, None);

    // The test drives the stage directly; stand the link chain up first.
    let dp = landscape_ebpf::chain::wan_link::WanLinkDataplane::new(
        rt.backbone().clone(),
        rt.xdp_attach().clone(),
        link_chain_id,
        Some(ifindex),
        true,
    )
    .expect("stand up wan link dataplane");

    let nat4 =
        landscape_ebpf::stages::nat4::attach_nat4(&dp, ifindex, true, &NatConfig::default(), addr)
            .expect("failed to start nat4 test");
    let nat6 = landscape_ebpf::stages::nat6::attach_nat6(
        &dp,
        ifindex,
        true,
        Some((std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0), 56)),
    )
    .expect("failed to start nat6 test");

    let _ = tokio::signal::ctrl_c().await;

    drop(nat4);
    drop(nat6);
    dp.close();
}
