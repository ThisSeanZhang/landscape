#[cfg(test)]
mod tests {
    use std::{
        mem::MaybeUninit,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use landscape_common::{
        flow::mark::FlowMark,
        ip_mark::{IpConfig, IpMarkInfo},
        route::RouteTargetInfo,
    };
    use libbpf_rs::{
        skel::{OpenSkel, SkelBuilder as _},
        ProgramInput,
    };
    use zerocopy::IntoBytes;

    use crate::{
        map_setting::{
            flow_wanip::create_inner_flow_match_map_v4, flow_wanip::create_inner_flow_match_map_v6,
            route::replace_wan_route_slots_v4_with_map, route::replace_wan_route_slots_v6_with_map,
        },
        tests::{
            route::package::{
                create_route_cache_inner_map_v4, create_route_cache_inner_map_v6,
                isolated_pin_root, lookup_rt4_cache_value, lookup_rt6_cache_value, simple_ipv4_tcp,
                simple_ipv6_tcp_syn, LAN_CACHE,
            },
            TestSkb,
        },
    };

    pub(crate) mod tc_lan_ingress_intro {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_intro.skel.rs"));
    }

    use tc_lan_ingress_intro::TcLanIngressIntroSkelBuilder;

    fn local_addr() -> Ipv6Addr {
        Ipv6Addr::from_str("fd00::10").unwrap()
    }

    fn remote_addr() -> Ipv6Addr {
        Ipv6Addr::from_str("2001:db8:2::20").unwrap()
    }

    /// Verify that tc_lan_ingress_route_v6 (the LAN ingress route worker in the
    /// tc_chain architecture) populates the LAN cache after a successful WAN
    /// redirect — the same behavior as the old route_lan_ingress.
    #[test]
    fn tc_lan_ingress_route_v6_populates_lan_cache_on_redirect() {
        let mut builder = TcLanIngressIntroSkelBuilder::default();
        let pin_root = isolated_pin_root("tc-lan-ingress-route-v6-cache");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        // Create LAN cache inner map so setting_cache_in_lan_v6 can write to it
        create_route_cache_inner_map_v6(&skel.maps.rt6_cache_map, LAN_CACHE);

        // Flow match: destination IP match in flow_id=0's inner IP trie →
        // mark=0x0305 (action=FLOW_REDIRECT, flow_id=5)
        let rules = vec![IpMarkInfo {
            mark: FlowMark::from(0x0305),
            cidr: IpConfig { ip: IpAddr::V6(remote_addr()), prefix: 128 },
            priority: 100,
        }];
        create_inner_flow_match_map_v6(&skel.maps.flow6_ip_map, 0, &rules).unwrap();

        // Route target: flow_id=5 → ifindex=11
        let targets = [(
            RouteTargetInfo {
                weight: 0,
                ifindex: 11,
                mac: None,
                default_route: false,
                is_docker: false,
                iface_name: "test-wan".to_string(),
                iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            1,
        )];
        replace_wan_route_slots_v6_with_map(&skel.maps.rt6_target_slot_map, 5, &targets);

        let mut packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());
        let mut ctx = TestSkb::default();
        ctx.ifindex = 6;

        let result = skel
            .progs
            .tc_lan_ingress_route_v6
            .test_run(ProgramInput {
                data_in: Some(&mut packet),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("run tc_lan_ingress_route_v6");

        // bpf_redirect returns TC_ACT_REDIRECT (7) on success
        assert_eq!(result.return_value as i32, 7);

        // Verify LAN cache was populated with the correct mark
        let cache_value = lookup_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            LAN_CACHE,
            local_addr(),
            remote_addr(),
        )
        .expect("LAN cache entry missing after redirect");

        assert_eq!(cache_value.mark_value, 0x0305);
    }

    fn local_v4_addr() -> Ipv4Addr {
        Ipv4Addr::from_str("192.168.1.10").unwrap()
    }

    fn remote_v4_addr() -> Ipv4Addr {
        Ipv4Addr::from_str("10.0.0.20").unwrap()
    }

    /// Verify that tc_lan_ingress_route_v4 (IPv4 route worker in the tc_chain
    /// architecture) populates the LAN cache after a successful WAN redirect.
    #[test]
    fn tc_lan_ingress_route_v4_populates_lan_cache_on_redirect() {
        let mut builder = TcLanIngressIntroSkelBuilder::default();
        let pin_root = isolated_pin_root("tc-lan-ingress-route-v4-cache");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        create_route_cache_inner_map_v4(&skel.maps.rt4_cache_map, LAN_CACHE);

        let rules = vec![IpMarkInfo {
            mark: FlowMark::from(0x0305),
            cidr: IpConfig { ip: IpAddr::V4(remote_v4_addr()), prefix: 32 },
            priority: 100,
        }];
        create_inner_flow_match_map_v4(&skel.maps.flow4_ip_map, 0, &rules).unwrap();

        let targets = [(
            RouteTargetInfo {
                weight: 0,
                ifindex: 11,
                mac: None,
                default_route: false,
                is_docker: false,
                iface_name: "test-wan".to_string(),
                iface_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                gateway_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            },
            1,
        )];
        replace_wan_route_slots_v4_with_map(&skel.maps.rt4_target_slot_map, 5, &targets);

        let mut packet = simple_ipv4_tcp(local_v4_addr(), remote_v4_addr());
        let mut ctx = TestSkb::default();
        ctx.ifindex = 6;

        let result = skel
            .progs
            .tc_lan_ingress_route_v4
            .test_run(ProgramInput {
                data_in: Some(&mut packet),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("run tc_lan_ingress_route_v4");

        assert_eq!(result.return_value as i32, 7);

        let cache_value = lookup_rt4_cache_value(
            &skel.maps.rt4_cache_map,
            LAN_CACHE,
            local_v4_addr(),
            remote_v4_addr(),
        )
        .expect("LAN cache entry missing after v4 redirect");

        assert_eq!(cache_value.mark_value, 0x0305);
    }
}
