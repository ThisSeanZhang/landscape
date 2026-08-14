use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use landscape_common::net::MacAddr;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags, ProgramInput,
};
use zerocopy::IntoBytes;

use crate::{
    map_setting::add_wan_ip,
    tests::{
        route::package::{
            as_bytes, create_route_cache_inner_map_v6, insert_ip_mac_v6, isolated_pin_root,
            lookup_rt6_cache_value, put_rt6_cache_ifindex, simple_ipv6_tcp_syn, WAN_CACHE,
        },
        TestSkb,
    },
};

#[allow(clippy::module_inception)]
pub(crate) mod test_route {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route.skel.rs"));
}

use test_route::TestRouteSkelBuilder;

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET_IFINDEX: u32 = 11;
    const WAN_IFINDEX: u32 = 6;

    fn local_addr() -> Ipv6Addr {
        Ipv6Addr::from_str("fd00::10").unwrap()
    }

    fn remote_addr() -> Ipv6Addr {
        Ipv6Addr::from_str("2001:db8:2::20").unwrap()
    }

    fn gateway_addr() -> Ipv6Addr {
        Ipv6Addr::from_str("2001:db8:ffff::1").unwrap()
    }

    fn put_rt6_target_slot(
        skel: &test_route::TestRouteSkel<'_>,
        flow_id: u32,
        slot: u32,
        ifindex: u32,
    ) {
        #[repr(C)]
        #[derive(Default, Clone, Copy)]
        struct RouteTargetSlotKeyV6 {
            flow_id: u32,
            slot: u32,
        }

        let key = RouteTargetSlotKeyV6 { flow_id, slot };

        let value = test_route::types::route_target_info_v6 {
            ifindex,
            has_mac: 0,
            is_docker: 0,
            ..Default::default()
        };

        skel.maps
            .rt6_target_slot_map
            .update(as_bytes(&key), as_bytes(&value), MapFlags::ANY)
            .expect("insert rt6 target slot");
    }

    #[test]
    fn v6_search_route_in_lan_uses_ip_mac_v6() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-search");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        create_route_cache_inner_map_v6(&skel.maps.rt6_cache_map, WAN_CACHE);
        put_rt6_cache_ifindex(
            &skel.maps.rt6_cache_map,
            WAN_CACHE,
            local_addr(),
            remote_addr(),
            TARGET_IFINDEX,
            true,
        );
        add_wan_ip(
            &skel.maps.wan_ip_binding,
            TARGET_IFINDEX,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8:ffff::10").unwrap()),
            Some(IpAddr::V6(gateway_addr())),
            64,
            None,
        );

        let next_hop_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
        let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
        insert_ip_mac_v6(
            &skel.maps.ip_mac_v6,
            remote_addr(),
            next_hop_mac,
            dev_mac,
            TARGET_IFINDEX,
        );

        let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());
        let mut packet_out = vec![0_u8; packet.len()];
        let result = skel
            .progs
            .test_route_v6_search_route_in_lan
            .test_run(ProgramInput {
                data_in: Some(&packet),
                data_out: Some(&mut packet_out),
                ..Default::default()
            })
            .expect("run test_route_v6_search_route_in_lan");

        assert_eq!(result.return_value as i32, 7);
        assert_eq!(&packet_out[0..6], &next_hop_mac.octets());
        assert_eq!(&packet_out[6..12], &dev_mac.octets());
        assert_eq!(&packet_out[12..14], &[0x86, 0xdd]);
    }

    #[test]
    fn v6_search_route_in_lan_falls_back_to_gateway_mac() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-gateway-fallback");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        create_route_cache_inner_map_v6(&skel.maps.rt6_cache_map, WAN_CACHE);
        put_rt6_cache_ifindex(
            &skel.maps.rt6_cache_map,
            WAN_CACHE,
            local_addr(),
            remote_addr(),
            TARGET_IFINDEX,
            true,
        );
        add_wan_ip(
            &skel.maps.wan_ip_binding,
            TARGET_IFINDEX,
            IpAddr::V6(Ipv6Addr::from_str("2001:db8:ffff::10").unwrap()),
            Some(IpAddr::V6(gateway_addr())),
            64,
            None,
        );

        let gateway_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
        let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();
        insert_ip_mac_v6(
            &skel.maps.ip_mac_v6,
            gateway_addr(),
            gateway_mac,
            dev_mac,
            TARGET_IFINDEX,
        );

        let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());
        let mut packet_out = vec![0_u8; packet.len()];
        let result = skel
            .progs
            .test_route_v6_search_route_in_lan
            .test_run(ProgramInput {
                data_in: Some(&packet),
                data_out: Some(&mut packet_out),
                ..Default::default()
            })
            .expect("run test_route_v6_search_route_in_lan gateway fallback");

        assert_eq!(result.return_value as i32, 7);
        assert_eq!(&packet_out[0..6], &gateway_mac.octets());
        assert_eq!(&packet_out[6..12], &dev_mac.octets());
        assert_eq!(&packet_out[12..14], &[0x86, 0xdd]);
    }

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

        let reverse = lookup_rt6_cache_value(
            &skel.maps.rt6_cache_map,
            WAN_CACHE,
            local_addr(),
            remote_addr(),
        )
        .expect("reverse WAN cache entry missing");
        assert_eq!(reverse.ifindex, WAN_IFINDEX);
        assert_eq!(reverse.has_mac, 1);

        assert!(
            lookup_rt6_cache_value(
                &skel.maps.rt6_cache_map,
                WAN_CACHE,
                remote_addr(),
                local_addr(),
            )
            .is_none(),
            "forward-direction WAN cache entry should not exist"
        );
    }

    #[test]
    fn default_flow_reads_target_from_slot_map() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-slot-priority");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        put_rt6_target_slot(&skel, 0, 0, 21);

        let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
        let result = skel
            .progs
            .test_route_v6_pick_wan_by_flow_id_default
            .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
            .expect("run test_route_v6_pick_wan_by_flow_id_default");

        assert_eq!(result.return_value as i32, 21);
    }

    #[test]
    fn non_default_flow_reads_target_from_slot_map() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-slot-non-default");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        put_rt6_target_slot(&skel, 5, 0, 21);

        let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
        let result = skel
            .progs
            .test_route_v6_pick_wan_by_flow_id_non_default
            .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
            .expect("run test_route_v6_pick_wan_by_flow_id_non_default");

        assert_eq!(result.return_value as i32, 21);
    }

    #[test]
    fn default_flow_without_slots_passes() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-slot-default-miss");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
        let result = skel
            .progs
            .test_route_v6_pick_wan_by_flow_id_default
            .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
            .expect("run test_route_v6_pick_wan_by_flow_id_default miss");

        assert_eq!(result.return_value as i32, -1);
    }

    #[test]
    fn non_default_flow_without_slots_drops() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-slot-non-default-miss");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        let packet = simple_ipv6_tcp_syn(Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED);
        let result = skel
            .progs
            .test_route_v6_pick_wan_by_flow_id_non_default
            .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
            .expect("run test_route_v6_pick_wan_by_flow_id_non_default miss");

        assert_eq!(result.return_value as i32, 2);
    }

    #[test]
    fn cached_docker_target_recovers_flow_vlan_id_from_mark() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-cached-docker-vlan");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());

        let result = skel
            .progs
            .test_route_cached_docker_vlan_id
            .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
            .expect("run cached docker vlan redirect");

        assert_eq!(result.return_value, 0xc05);
    }

    #[test]
    fn cached_docker_vlan_push_uses_flow_vlan_id_from_mark() {
        let mut builder = TestRouteSkelBuilder::default();
        let pin_root = isolated_pin_root("route-helper-v6-cached-docker-vlan-push");
        builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

        let mut open_object = MaybeUninit::uninit();
        let open = builder.open(&mut open_object).unwrap();
        let skel = open.load().unwrap();

        let packet = simple_ipv6_tcp_syn(local_addr(), remote_addr());

        let result = skel
            .progs
            .test_route_cached_docker_redirect_v6
            .test_run(ProgramInput { data_in: Some(&packet), ..Default::default() })
            .expect("run cached docker vlan push");

        assert_eq!(result.return_value, 0x0c05);
    }
}
