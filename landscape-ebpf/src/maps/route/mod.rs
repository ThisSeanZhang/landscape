//! Route domain: LAN prefix routes (`rt4/6_lan_map`), per-flow WAN target
//! slots (`rt4/6_target_slot_map`), the verdict cache (`rt4/6_cache_map`) and
//! webserver-facing flow-verdict tracing.
//!
//! * `lan.rs` — LAN prefix route writes
//! * `wan.rs` — per-flow WAN target-slot writes
//! * `trace.rs` — flow match/verdict/cache queries
//! * `cache.rs` — verdict cache inner-map lifecycle

pub mod cache;
mod init;
mod lan;
mod trace;
pub(crate) mod types;
mod wan;

pub use init::*;
pub use lan::*;
pub use trace::*;
pub use wan::*;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use landscape_common::{
        flow::mark::FlowMark,
        flow::trace::{FlowMatchSource, FlowRuleMatchResult, FlowVerdictSource},
        sys_service::route_service::{RouteTargetInfo, WanRouteTarget},
    };
    use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, libbpf_sys};
    use zerocopy::{FromBytes, IntoBytes};

    use super::types::{Route6SlotKey, Route6TargetInfo, RouteFlowTargetKey};
    use super::*;

    fn dummy_v6(ifindex: u32) -> RouteTargetInfo {
        RouteTargetInfo::dummy(ifindex, "", IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    }

    fn create_test_slot_map_v6() -> MapHandle {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        MapHandle::create(
            MapType::Hash,
            None::<&str>,
            std::mem::size_of::<Route6SlotKey>() as u32,
            std::mem::size_of::<Route6TargetInfo>() as u32,
            1024,
            &opts,
        )
        .expect("create test slot map v6")
    }

    fn create_test_flow_targets_v6() -> MapHandle {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        MapHandle::create(
            MapType::Hash,
            None::<&str>,
            std::mem::size_of::<RouteFlowTargetKey>() as u32,
            std::mem::size_of::<Route6TargetInfo>() as u32,
            64,
            &opts,
        )
        .expect("create test flow targets map v6")
    }

    #[allow(clippy::field_reassign_with_default)]
    fn insert_v6_slot(map: &MapHandle, flow_id: u32, slot: u32, ifindex: u32) {
        let mut key = Route6SlotKey::default();
        key.flow_id = flow_id;
        key.slot = slot;

        let mut value = Route6TargetInfo::default();
        value.ifindex = ifindex;

        map.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
            .expect("insert test slot entry");
    }

    #[allow(clippy::field_reassign_with_default)]
    fn lookup_v6_slot(map: &MapHandle, flow_id: u32, slot: u32) -> bool {
        let mut key = Route6SlotKey::default();
        key.flow_id = flow_id;
        key.slot = slot;
        map.lookup(key.as_bytes(), MapFlags::ANY).is_ok_and(|v| v.is_some())
    }

    #[test]
    fn replace_slots_with_all_zero_weights_clears_existing_entries() {
        let map = create_test_slot_map_v6();
        let flow_targets = create_test_flow_targets_v6();

        // Pre-populate some slots and flow_targets for flow_id 5
        insert_v6_slot(&map, 5, 0, 11);
        insert_v6_slot(&map, 5, 1, 11);
        flow_targets
            .update(
                RouteFlowTargetKey { flow_id: 5, ifindex: 11 }.as_bytes(),
                Route6TargetInfo { ifindex: 11, ..Default::default() }.as_bytes(),
                MapFlags::ANY,
            )
            .unwrap();
        assert!(lookup_v6_slot(&map, 5, 0));
        assert!(lookup_v6_slot(&map, 5, 1));

        // Call replace with all-zero weights
        let zero_weight_target = (WanRouteTarget::link(0, dummy_v6(11)), 0);
        replace_wan_route_slots_v6_with_map(&map, &flow_targets, 5, &[zero_weight_target]);

        // Slots and flow_targets should be cleared
        assert!(!lookup_v6_slot(&map, 5, 0));
        assert!(!lookup_v6_slot(&map, 5, 1));
        assert!(
            flow_targets
                .lookup(RouteFlowTargetKey { flow_id: 5, ifindex: 11 }.as_bytes(), MapFlags::ANY)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn replace_slots_store_chain_in_values() {
        let map = create_test_slot_map_v6();
        let flow_targets = create_test_flow_targets_v6();

        let target = (WanRouteTarget::link(7, dummy_v6(11)), 3);
        replace_wan_route_slots_v6_with_map(&map, &flow_targets, 5, &[target]);

        // Every slot of flow 5 carries the target's chain for the WAN
        // egress chain dispatch.
        for slot in 0..256u32 {
            let key = Route6SlotKey { flow_id: 5, slot };
            let bytes = map
                .lookup(key.as_bytes(), MapFlags::ANY)
                .expect("lookup slot")
                .expect("slot filled");
            let value = Route6TargetInfo::read_from_bytes(&bytes).expect("decode slot value");
            assert_eq!(
                value,
                Route6TargetInfo {
                    ifindex: 11,
                    has_mac: 0,
                    is_docker: 0,
                    link_chain_id: 7
                }
            );
        }

        let ft_bytes = flow_targets
            .lookup(RouteFlowTargetKey { flow_id: 5, ifindex: 11 }.as_bytes(), MapFlags::ANY)
            .expect("lookup flow target")
            .expect("flow target populated");
        let ft_val = Route6TargetInfo::read_from_bytes(&ft_bytes).expect("decode flow target");
        assert_eq!(ft_val.ifindex, 11);
        assert_eq!(ft_val.link_chain_id, 7);
    }

    #[test]
    fn replace_slots_filters_family_and_preserves_forwarding_flags() {
        use super::types::{Route4SlotKey, Route4TargetInfo};
        use crate::maps::create_map_handle;

        let mut eth = RouteTargetInfo::dummy(11, "wan", IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        eth.mac = Some([0x02, 0, 0, 0, 0, 0x11].into());
        let (_, docker) = RouteTargetInfo::new_docker(12, "docker");
        let targets = [(WanRouteTarget::link(0x123, eth), 1), (WanRouteTarget::netns(docker), 1)];
        let v4 = create_map_handle(&RT4_SLOT_MAP_SPEC).unwrap();
        let v6 = create_map_handle(&RT6_SLOT_MAP_SPEC).unwrap();
        let ft4 = create_map_handle(&RT4_FLOW_TARGETS_SPEC).unwrap();
        let ft6 = create_map_handle(&RT6_FLOW_TARGETS_SPEC).unwrap();
        replace_wan_route_slots_v4_with_map(&v4, &ft4, 5, &targets);
        replace_wan_route_slots_v6_with_map(&v6, &ft6, 5, &targets);

        for slot in 0..256 {
            let key4 = Route4SlotKey { flow_id: 5, slot };
            let key6 = Route6SlotKey { flow_id: 5, slot };
            let bytes4 = v4.lookup(key4.as_bytes(), MapFlags::ANY).unwrap().unwrap();
            let bytes6 = v6.lookup(key6.as_bytes(), MapFlags::ANY).unwrap().unwrap();
            assert_eq!(
                Route4TargetInfo::read_from_bytes(&bytes4).unwrap(),
                Route4TargetInfo {
                    ifindex: 11,
                    has_mac: 1,
                    is_docker: 0,
                    link_chain_id: 0x123
                }
            );
            assert_eq!(
                Route6TargetInfo::read_from_bytes(&bytes6).unwrap(),
                Route6TargetInfo {
                    ifindex: 12,
                    has_mac: 1,
                    is_docker: 1,
                    link_chain_id: 0
                }
            );
        }

        let ft4_bytes = ft4
            .lookup(RouteFlowTargetKey { flow_id: 5, ifindex: 11 }.as_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();
        let ft6_bytes = ft6
            .lookup(RouteFlowTargetKey { flow_id: 5, ifindex: 12 }.as_bytes(), MapFlags::ANY)
            .unwrap()
            .unwrap();
        assert_eq!(
            Route4TargetInfo::read_from_bytes(&ft4_bytes).unwrap(),
            Route4TargetInfo {
                ifindex: 11,
                has_mac: 1,
                is_docker: 0,
                link_chain_id: 0x123
            }
        );
        assert_eq!(
            Route6TargetInfo::read_from_bytes(&ft6_bytes).unwrap(),
            Route6TargetInfo {
                ifindex: 12,
                has_mac: 1,
                is_docker: 1,
                link_chain_id: 0
            }
        );
    }

    #[test]
    fn set_flow_balance_mode_maintains_any_five_tuple_summary_slot() {
        use crate::maps::create_map_handle;
        use landscape_common::flow::FlowBalanceMode;

        let mode_map = create_map_handle(&RT_FLOW_MODE_MAP_SPEC).unwrap();
        let read_byte = |key: u32| -> u8 {
            mode_map.lookup(key.as_bytes(), MapFlags::ANY).unwrap().unwrap()[0]
        };

        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 0);

        set_flow_balance_mode_with_map(&mode_map, 5, FlowBalanceMode::FiveTuple);
        assert_eq!(read_byte(5), 1);
        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 1);

        set_flow_balance_mode_with_map(&mode_map, 6, FlowBalanceMode::FiveTuple);
        set_flow_balance_mode_with_map(&mode_map, 5, FlowBalanceMode::DstIp);
        assert_eq!(read_byte(5), 0);
        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 1);

        set_flow_balance_mode_with_map(&mode_map, 6, FlowBalanceMode::DstIp);
        assert_eq!(read_byte(6), 0);
        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 0);
    }

    #[test]
    fn clearing_retired_flow_id_resets_any_five_tuple_summary_to_zero() {
        use crate::maps::create_map_handle;
        use landscape_common::flow::FlowBalanceMode;

        let mode_map = create_map_handle(&RT_FLOW_MODE_MAP_SPEC).unwrap();
        let read_byte = |key: u32| -> u8 {
            mode_map.lookup(key.as_bytes(), MapFlags::ANY).unwrap().unwrap()[0]
        };

        // Flow 5 starts in FiveTuple mode, then is edited in-place to flow 6 (DstIp).
        set_flow_balance_mode_with_map(&mode_map, 5, FlowBalanceMode::FiveTuple);
        assert_eq!(read_byte(5), 1);
        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 1);

        // Updating flow 6 alone leaves slot 5 and summary slot 256 set to 1.
        set_flow_balance_mode_with_map(&mode_map, 6, FlowBalanceMode::DstIp);
        assert_eq!(read_byte(6), 0);
        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 1);

        // Clearing retired flow_id 5 resets both slot 5 and summary slot 256 to 0.
        set_flow_balance_mode_with_map(&mode_map, 5, FlowBalanceMode::DstIp);
        assert_eq!(read_byte(5), 0);
        assert_eq!(read_byte(ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY), 0);
    }

    #[test]
    fn pick_effective_flow_prefers_ip_then_mac_then_default() {
        assert_eq!(
            pick_effective_flow(Some(3), Some(7), FlowMatchSource::Ipv4),
            (7, FlowMatchSource::Ipv4)
        );
        assert_eq!(
            pick_effective_flow(Some(3), None, FlowMatchSource::Ipv4),
            (3, FlowMatchSource::Mac)
        );
        assert_eq!(
            pick_effective_flow(None, None, FlowMatchSource::Ipv4),
            (0, FlowMatchSource::Default)
        );
    }

    #[test]
    fn expected_cache_mark_value_expands_keep_going_flow_id() {
        let keep_going = FlowMark::from(0x0000);
        let direct = FlowMark::from(0x0100);
        let redirect = FlowMark::from(0x0305);

        assert_eq!(expected_cache_mark_value(9, &keep_going), 0x0009);
        assert_eq!(expected_cache_mark_value(9, &direct), 0x0100);
        assert_eq!(expected_cache_mark_value(9, &redirect), 0x0305);
    }

    #[test]
    fn compute_effective_mark_prefers_dns_on_equal_priority() {
        let ip_rule = Some(FlowRuleMatchResult { mark: FlowMark::from(0x0100), priority: 10 });
        let dns_rule = Some(FlowRuleMatchResult { mark: FlowMark::from(0x0305), priority: 10 });

        let (source, mark) = compute_effective_mark(&ip_rule, &dns_rule);
        let mark_value: u32 = mark.into();

        assert_eq!(source, FlowVerdictSource::DnsRule);
        assert_eq!(mark_value, 0x0305);
    }
}
