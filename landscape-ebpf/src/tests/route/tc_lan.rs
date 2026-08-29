#[cfg(test)]
mod tests {
    use std::{
        mem::MaybeUninit,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use landscape_common::{
        flow::ip_mark::{IpConfig, IpMarkInfo},
        flow::mark::FlowMark,
        sys_service::route_service::RouteTargetInfo,
    };
    use libbpf_rs::{
        skel::{OpenSkel, SkelBuilder as _},
        MapCore, MapFlags, ProgramInput,
    };
    use zerocopy::IntoBytes;

    use crate::{
        map_setting::{
            flow_wanip::create_inner_flow_match_map_v4, flow_wanip::create_inner_flow_match_map_v6,
            route::replace_wan_route_slots_v4_with_map, route::replace_wan_route_slots_v6_with_map,
            share_map::types::mac_key_v6,
        },
        tests::{
            route::package::{
                as_bytes, create_route_cache_inner_map_v4, create_route_cache_inner_map_v6,
                isolated_pin_root, lookup_rt4_cache_value, lookup_rt6_cache_value, simple_ipv4_tcp,
                simple_ipv6_ns_dad, simple_ipv6_tcp_syn, LAN_CACHE,
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

        let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());
        let mut ctx = TestSkb { ifindex: 6, ..Default::default() };

        let result = skel
            .progs
            .tc_lan_ingress_route_v6
            .test_run(ProgramInput {
                data_in: Some(&packet),
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

        let packet = simple_ipv4_tcp(local_v4_addr(), remote_v4_addr());
        let mut ctx = TestSkb { ifindex: 6, ..Default::default() };

        let result = skel
            .progs
            .tc_lan_ingress_route_v4
            .test_run(ProgramInput {
                data_in: Some(&packet),
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

    pub(crate) mod tc_lan_dao {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_dao.skel.rs"));
    }

    use tc_lan_dao::TcLanDaoSkelBuilder;

    const CLIENT_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const TEST_IFINDEX: u32 = 6;

    fn lookup_mac_v6<T: MapCore>(map: &T, addr: Ipv6Addr) -> Option<([u8; 6], u32)> {
        let mut key = mac_key_v6::default();
        key.addr.bytes = addr.to_bits().to_be_bytes();
        map.lookup(as_bytes(&key), MapFlags::ANY).expect("lookup ip_mac_v6").map(|bytes| {
            assert_eq!(bytes.len(), 20, "mac_value_v6 size");
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&bytes[4..10]);
            let ifindex = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
            (mac, ifindex)
        })
    }

    fn load_tc_lan_dao_skel(
    ) -> (tc_lan_dao::TcLanDaoSkel<'static>, TestSkb, crate::landscape::OwnedOpenObject) {
        let mut builder = TcLanDaoSkelBuilder::default();
        let pin_root = isolated_pin_root("tc-lan-dao-direct");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let (backing, obj) = crate::landscape::OwnedOpenObject::new();
        let open = builder.open(obj).unwrap();
        let skel = open.load().unwrap();
        let ctx = TestSkb {
            ingress_ifindex: TEST_IFINDEX,
            ifindex: TEST_IFINDEX,
            ..Default::default()
        };
        (skel, ctx, backing)
    }

    fn run_on_skel(
        skel: &tc_lan_dao::TcLanDaoSkel<'static>,
        ctx: &mut TestSkb,
        packet: &[u8],
    ) -> i32 {
        skel.progs
            .tc_lan_dao
            .test_run(ProgramInput {
                data_in: Some(packet),
                context_in: Some(ctx.as_mut_bytes()),
                ..Default::default()
            })
            .expect("run tc_lan_dao")
            .return_value as i32
    }

    /// Loads the DAO skel, lets `setup` mutate the skel (e.g. pre-insert map
    /// entries) before the program runs, runs the program on `packet`, lets
    /// `check` inspect the skel, then tears everything down in the explicit
    /// order required by the skel's ownership model.
    fn run_dao_case_with_setup(
        packet: &[u8],
        setup: impl FnOnce(&mut tc_lan_dao::TcLanDaoSkel<'static>),
        check: impl FnOnce(&tc_lan_dao::TcLanDaoSkel<'static>),
    ) -> i32 {
        let (mut skel, mut ctx, backing) = load_tc_lan_dao_skel();
        setup(&mut skel);
        let ret = run_on_skel(&skel, &mut ctx, packet);
        check(&skel);
        drop(skel);
        // `let _ =` instead of `drop`: TestSkb is Copy (drop would be a no-op
        // flagged by clippy::drop_copy), but keeping the explicit teardown in
        // order is harmless and stays correct if TestSkb stops being Copy.
        let _ = ctx;
        drop(backing);
        ret
    }

    /// Convenience wrapper without a pre-run setup.
    fn run_dao_case(packet: &[u8], check: impl FnOnce(&tc_lan_dao::TcLanDaoSkel<'static>)) -> i32 {
        run_dao_case_with_setup(packet, |_| {}, check)
    }

    /// A DAD NS (src `::`, dst solicited-node multicast, target /128) must be
    /// learned into ip_mac_v6 and passed through (TC_ACT_UNSPEC).
    #[test]
    fn tc_lan_dao_learns_dad_ns() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let ret = run_dao_case(&simple_ipv6_ns_dad(CLIENT_MAC, target), |skel| {
            let (mac, ifindex) =
                lookup_mac_v6(&skel.maps.ip_mac_v6, target).expect("DAD NS must be learned");
            assert_eq!(mac, CLIENT_MAC, "learned MAC must come from the Ethernet source");
            assert_eq!(ifindex, TEST_IFINDEX);
        });
        assert_eq!(ret, -1, "expected TC_ACT_UNSPEC");
    }

    /// Non-solicited-node destination must not be learned.
    #[test]
    fn tc_lan_dao_skips_unicast_dst() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let mut packet = simple_ipv6_ns_dad(CLIENT_MAC, target);
        // overwrite the IPv6 daddr (offset 14 + 24) with a unicast address
        let unicast_dst = Ipv6Addr::from_str("fd00::2").unwrap();
        packet[38..54].copy_from_slice(&unicast_dst.octets());

        let ret = run_dao_case(&packet, |skel| {
            assert!(lookup_mac_v6(&skel.maps.ip_mac_v6, target).is_none());
        });
        assert_eq!(ret, -1);
    }

    /// A solicited-node multicast that is not derived from the target must not
    /// be learned (RFC 4861: ff02::1:ffXX:XXXX uses the target's last 24 bits).
    #[test]
    fn tc_lan_dao_skips_wrong_solicited_node() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let mut packet = simple_ipv6_ns_dad(CLIENT_MAC, target);
        // overwrite the IPv6 daddr (offset 14 + 24) with the solicited-node
        // multicast of a different address (fd00::2)
        let other_snma = Ipv6Addr::from_str("ff02::1:ff00:2").unwrap();
        packet[38..54].copy_from_slice(&other_snma.octets());

        let ret = run_dao_case(&packet, |skel| {
            assert!(lookup_mac_v6(&skel.maps.ip_mac_v6, target).is_none());
        });
        assert_eq!(ret, -1);
    }

    /// The Ethernet destination must be the solicited-node multicast MAC of
    /// the target itself.
    #[test]
    fn tc_lan_dao_skips_wrong_dst_mac() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let mut packet = simple_ipv6_ns_dad(CLIENT_MAC, target);
        // overwrite the Ethernet dst MAC (offset 0..6) with the solicited-node
        // multicast MAC of a different address (fd00::2)
        packet[0..6].copy_from_slice(&[0x33, 0x33, 0xff, 0x00, 0x00, 0x02]);

        let ret = run_dao_case(&packet, |skel| {
            assert!(lookup_mac_v6(&skel.maps.ip_mac_v6, target).is_none());
        });
        assert_eq!(ret, -1);
    }

    /// Non-unspecified IPv6 source must not be learned (not DAD).
    #[test]
    fn tc_lan_dao_skips_non_unspecified_src() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let mut packet = simple_ipv6_ns_dad(CLIENT_MAC, target);
        // overwrite the IPv6 saddr (offset 14 + 8) with a real source address
        let src = Ipv6Addr::from_str("fd00::10").unwrap();
        packet[22..38].copy_from_slice(&src.octets());

        let ret = run_dao_case(&packet, |skel| {
            assert!(lookup_mac_v6(&skel.maps.ip_mac_v6, target).is_none());
        });
        assert_eq!(ret, -1);
    }

    /// Non-NS ICMPv6 (e.g. echo request) must not be learned.
    #[test]
    fn tc_lan_dao_skips_non_ns_icmp() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let mut packet = simple_ipv6_ns_dad(CLIENT_MAC, target);
        packet[54] = 128; // ICMPv6 type = echo request

        let ret = run_dao_case(&packet, |skel| {
            assert!(lookup_mac_v6(&skel.maps.ip_mac_v6, target).is_none());
        });
        assert_eq!(ret, -1);
    }

    /// Link-local targets must not be learned.
    #[test]
    fn tc_lan_dao_skips_link_local_target() {
        let target = Ipv6Addr::from_str("fe80::1").unwrap();
        let ret = run_dao_case(&simple_ipv6_ns_dad(CLIENT_MAC, target), |skel| {
            assert!(lookup_mac_v6(&skel.maps.ip_mac_v6, target).is_none());
        });
        assert_eq!(ret, -1);
    }

    /// An existing binding must not be overwritten by a DAD frame: the
    /// program inserts with BPF_NOEXIST, so the pre-existing entry must
    /// survive the DAD NS run untouched.
    #[test]
    fn tc_lan_dao_does_not_overwrite_existing() {
        let target = Ipv6Addr::from_str("fd00::1").unwrap();
        let existing_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ret = run_dao_case_with_setup(
            &simple_ipv6_ns_dad(CLIENT_MAC, target),
            |skel| {
                let mut key = mac_key_v6::default();
                key.addr.bytes = target.to_bits().to_be_bytes();
                let mut existing = vec![0u8; 20];
                existing[4..10].copy_from_slice(&existing_mac);
                existing[10..16].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
                existing[16..18].copy_from_slice(&0x86dd_u16.to_be_bytes());
                skel.maps
                    .ip_mac_v6
                    .update(as_bytes(&key), &existing, MapFlags::ANY)
                    .expect("pre-insert binding");
            },
            |skel| {
                let (mac, ifindex) =
                    lookup_mac_v6(&skel.maps.ip_mac_v6, target).expect("binding must still exist");
                assert_eq!(
                    mac, existing_mac,
                    "existing binding must not be overwritten by a DAD frame"
                );
                assert_eq!(ifindex, 0, "existing binding must not be overwritten");
            },
        );
        assert_eq!(ret, -1);
    }
}
