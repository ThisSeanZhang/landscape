use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};
use zerocopy::IntoBytes;

use crate::tests::{
    isolated_pin_root,
    route::{
        map_helper::{
            create_route_cache_inner_map_v6, local_addr, lookup_rt6_cache_value, remote_addr,
            WAN_CACHE, WAN_IFINDEX,
        },
        packet_builder::simple_ipv6_tcp_syn,
        test_route::TestRouteSkelBuilder,
    },
    TestSkb,
};

#[test]
fn v6_setting_cache_in_wan_writes_reverse_key() {
    let mut builder = TestRouteSkelBuilder::default();
    let pin_root = isolated_pin_root("route-helper-v6-wan-cache");
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut open_object = MaybeUninit::uninit();
    let open = builder.open(&mut open_object).unwrap();
    let skel = open.load().unwrap();

    create_route_cache_inner_map_v6(&skel.maps.rt6_cache_map, WAN_CACHE);

    let packet = simple_ipv6_tcp_syn(remote_addr(), local_addr());
    let mut ctx = TestSkb { ifindex: WAN_IFINDEX, ..Default::default() };

    let result = skel
        .progs
        .test_route_v6_setting_cache_in_wan
        .test_run(ProgramInput {
            data_in: Some(&packet),
            context_in: Some(ctx.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run test_route_v6_setting_cache_in_wan");

    assert_eq!(result.return_value as i32, 0);

    let reverse =
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, local_addr(), remote_addr())
            .expect("reverse WAN cache entry missing");
    assert_eq!(reverse.ifindex, WAN_IFINDEX);
    assert_eq!(reverse.has_mac, 1);

    assert!(
        lookup_rt6_cache_value(&skel.maps.rt6_cache_map, WAN_CACHE, remote_addr(), local_addr(),)
            .is_none(),
        "forward-direction WAN cache entry should not exist"
    );
}
