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
        sys_service::route_service::RouteTargetInfo,
    };
    use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
    use zerocopy::IntoBytes;

    use super::types::{RouteTargetInfoV6, RouteTargetSlotKeyV6};
    use super::*;

    fn dummy_v6_route_target(ifindex: u32) -> RouteTargetInfo {
        RouteTargetInfo {
            weight: 0,
            ifindex,
            mac: None,
            default_route: false,
            is_docker: false,
            iface_name: String::new(),
            iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
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
            std::mem::size_of::<RouteTargetSlotKeyV6>() as u32,
            std::mem::size_of::<RouteTargetInfoV6>() as u32,
            256,
            &opts,
        )
        .expect("create test slot map v6")
    }

    #[allow(clippy::field_reassign_with_default)]
    fn insert_v6_slot(map: &MapHandle, flow_id: u32, slot: u32, ifindex: u32) {
        let mut key = RouteTargetSlotKeyV6::default();
        key.flow_id = flow_id;
        key.slot = slot;

        let mut value = RouteTargetInfoV6::default();
        value.ifindex = ifindex;

        map.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY)
            .expect("insert test slot entry");
    }

    #[allow(clippy::field_reassign_with_default)]
    fn lookup_v6_slot(map: &MapHandle, flow_id: u32, slot: u32) -> bool {
        let mut key = RouteTargetSlotKeyV6::default();
        key.flow_id = flow_id;
        key.slot = slot;
        map.lookup(key.as_bytes(), MapFlags::ANY).is_ok_and(|v| v.is_some())
    }

    #[test]
    fn replace_slots_with_all_zero_weights_clears_existing_entries() {
        let map = create_test_slot_map_v6();

        // Pre-populate some slots for flow_id 5
        insert_v6_slot(&map, 5, 0, 11);
        insert_v6_slot(&map, 5, 1, 11);
        assert!(lookup_v6_slot(&map, 5, 0));
        assert!(lookup_v6_slot(&map, 5, 1));

        // Call replace with all-zero weights
        let zero_weight_target = (dummy_v6_route_target(11), 0);
        replace_wan_route_slots_v6_with_map(&map, 5, &[zero_weight_target]);

        // Slots should be cleared
        assert!(!lookup_v6_slot(&map, 5, 0));
        assert!(!lookup_v6_slot(&map, 5, 1));
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
