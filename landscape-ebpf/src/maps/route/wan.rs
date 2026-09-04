//! Per-flow WAN target-slot maps (`rt4/6_target_slot_map`): weighted-slot
//! replacement/clear keyed by flow_id.

use std::net::IpAddr;

use landscape_common::config::FlowId;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::IntoBytes;

use crate::{
    maps::{RouteTargetInfoV4, RouteTargetInfoV6, RouteTargetSlotKeyV4, RouteTargetSlotKeyV6},
    MAP_PATHS,
};
const FLOW_TARGET_SLOT_COUNT: usize = 16;
pub fn replace_wan_route_slots_v4(flow_id: FlowId, targets: &[(RouteTargetInfo, u32)]) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_target_slot_map).unwrap();
    replace_wan_route_slots_v4_with_map(&rt_target_map, flow_id, targets);
}

pub fn replace_wan_route_slots_v6(flow_id: FlowId, targets: &[(RouteTargetInfo, u32)]) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_target_slot_map).unwrap();
    replace_wan_route_slots_v6_with_map(&rt_target_map, flow_id, targets);
}

pub fn del_wan_route_slots_v4(flow_id: FlowId) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt4_target_slot_map).unwrap();
    clear_wan_route_slots_v4(&rt_target_map, flow_id);
}

pub fn del_wan_route_slots_v6(flow_id: FlowId) {
    let rt_target_map =
        libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.rt6_target_slot_map).unwrap();
    clear_wan_route_slots_v6(&rt_target_map, flow_id);
}

fn build_slot_indices(weights: &[u32]) -> Vec<usize> {
    let total_weight: u32 = weights.iter().sum();
    if total_weight == 0 {
        return Vec::new();
    }

    let mut current = vec![0i64; weights.len()];
    let mut slots = Vec::with_capacity(FLOW_TARGET_SLOT_COUNT);
    for _ in 0..FLOW_TARGET_SLOT_COUNT {
        let mut best_idx = None;
        let mut best_score = i64::MIN;
        for (idx, weight) in weights.iter().enumerate() {
            if *weight == 0 {
                continue;
            }
            current[idx] += *weight as i64;
            if current[idx] > best_score {
                best_score = current[idx];
                best_idx = Some(idx);
            }
        }

        let Some(best_idx) = best_idx else {
            break;
        };

        current[best_idx] -= total_weight as i64;
        slots.push(best_idx);
    }
    slots
}

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn replace_wan_route_slots_v4_with_map<T>(
    rt_target_map: &T,
    flow_id: FlowId,
    targets: &[(RouteTargetInfo, u32)],
) where
    T: MapCore,
{
    let filtered: Vec<_> = targets
        .iter()
        .filter(|(target, weight)| *weight > 0 && matches!(target.gateway_ip, IpAddr::V4(_)))
        .collect();
    if filtered.is_empty() {
        clear_wan_route_slots_v4(rt_target_map, flow_id);
        return;
    }

    let weights: Vec<u32> = filtered.iter().map(|(_, weight)| *weight).collect();
    let slots = build_slot_indices(&weights);
    let slot_count = slots.len() as u32;
    let mut keys = Vec::with_capacity(slots.len() * std::mem::size_of::<RouteTargetSlotKeyV4>());
    let mut values = Vec::with_capacity(slots.len() * std::mem::size_of::<RouteTargetInfoV4>());

    for (slot, target_index) in slots.into_iter().enumerate() {
        let (target, _) = filtered[target_index];
        let mut key = RouteTargetSlotKeyV4::default();
        key.flow_id = flow_id;
        key.slot = slot as u32;

        let mut value = RouteTargetInfoV4::default();
        value.ifindex = target.ifindex;
        value.is_docker = u8::from(target.is_docker);
        if let IpAddr::V4(ipv4_addr) = target.gateway_ip {
            value.gate_addr = ipv4_addr.to_bits().to_be();
        }
        match target.mac {
            Some(mac) => {
                value.has_mac = 1;
                value.mac = mac.octets();
            }
            None => value.has_mac = 0,
        }

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
    }

    if let Err(e) =
        rt_target_map.update_batch(&keys, &values, slot_count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("replace ipv4 wan slot batch error:{e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
pub(crate) fn replace_wan_route_slots_v6_with_map<T>(
    rt_target_map: &T,
    flow_id: FlowId,
    targets: &[(RouteTargetInfo, u32)],
) where
    T: MapCore,
{
    let filtered: Vec<_> = targets
        .iter()
        .filter(|(target, weight)| *weight > 0 && matches!(target.gateway_ip, IpAddr::V6(_)))
        .collect();
    if filtered.is_empty() {
        clear_wan_route_slots_v6(rt_target_map, flow_id);
        return;
    }

    let weights: Vec<u32> = filtered.iter().map(|(_, weight)| *weight).collect();
    let slots = build_slot_indices(&weights);
    let slot_count = slots.len() as u32;
    let mut keys = Vec::with_capacity(slots.len() * std::mem::size_of::<RouteTargetSlotKeyV6>());
    let mut values = Vec::with_capacity(slots.len() * std::mem::size_of::<RouteTargetInfoV6>());

    for (slot, target_index) in slots.into_iter().enumerate() {
        let (target, _) = filtered[target_index];
        let mut key = RouteTargetSlotKeyV6::default();
        key.flow_id = flow_id;
        key.slot = slot as u32;

        let mut value = RouteTargetInfoV6::default();
        value.ifindex = target.ifindex;
        value.is_docker = u8::from(target.is_docker);
        if let IpAddr::V6(ipv6_addr) = target.gateway_ip {
            value.gate_addr = ipv6_addr.to_bits().to_be_bytes();
        }
        match target.mac {
            Some(mac) => {
                value.has_mac = 1;
                value.mac = mac.octets();
            }
            None => value.has_mac = 0,
        }

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
    }

    if let Err(e) =
        rt_target_map.update_batch(&keys, &values, slot_count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("replace ipv6 wan slot batch error:{e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
fn clear_wan_route_slots_v4<T>(rt_target_map: &T, flow_id: FlowId)
where
    T: MapCore,
{
    let mut keys =
        Vec::with_capacity(FLOW_TARGET_SLOT_COUNT * std::mem::size_of::<RouteTargetSlotKeyV4>());
    let mut count = 0;
    for slot in 0..FLOW_TARGET_SLOT_COUNT as u32 {
        let mut key = RouteTargetSlotKeyV4::default();
        key.flow_id = flow_id;
        key.slot = slot;
        let key_bytes = key.as_bytes();
        match rt_target_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(_)) => {
                count += 1;
                keys.extend_from_slice(key_bytes);
            }
            Ok(None) => {}
            Err(e) => tracing::error!("lookup ipv4 wan slot before delete error:{e:?}"),
        }
    }

    if count > 0 {
        if let Err(e) = rt_target_map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY) {
            tracing::error!("delete ipv4 wan slot batch error:{e:?}");
        }
    }
}

#[allow(clippy::field_reassign_with_default)]
fn clear_wan_route_slots_v6<T>(rt_target_map: &T, flow_id: FlowId)
where
    T: MapCore,
{
    let mut keys =
        Vec::with_capacity(FLOW_TARGET_SLOT_COUNT * std::mem::size_of::<RouteTargetSlotKeyV6>());
    let mut count = 0;
    for slot in 0..FLOW_TARGET_SLOT_COUNT as u32 {
        let mut key = RouteTargetSlotKeyV6::default();
        key.flow_id = flow_id;
        key.slot = slot;
        let key_bytes = key.as_bytes();
        match rt_target_map.lookup(key_bytes, MapFlags::ANY) {
            Ok(Some(_)) => {
                count += 1;
                keys.extend_from_slice(key_bytes);
            }
            Ok(None) => {}
            Err(e) => tracing::error!("lookup ipv6 wan slot before delete error:{e:?}"),
        }
    }

    if count > 0 {
        if let Err(e) = rt_target_map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY) {
            tracing::error!("delete ipv6 wan slot batch error:{e:?}");
        }
    }
}

#[cfg(test)]
mod slot_tests {
    use super::build_slot_indices;

    fn counts(slots: &[usize], target_count: usize) -> Vec<usize> {
        let mut counts = vec![0; target_count];
        for &slot in slots {
            counts[slot] += 1;
        }
        counts
    }

    #[test]
    fn slot_builder_balances_equal_weights() {
        let slots = build_slot_indices(&[1, 1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 2), vec![8, 8]);
    }

    #[test]
    fn slot_builder_respects_three_to_one_ratio() {
        let slots = build_slot_indices(&[3, 1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 2), vec![12, 4]);
    }

    #[test]
    fn slot_builder_skips_zero_weight_targets() {
        let slots = build_slot_indices(&[2, 0, 1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 3), vec![11, 0, 5]);
    }

    #[test]
    fn slot_builder_fills_all_slots_for_single_target() {
        let slots = build_slot_indices(&[1]);
        assert_eq!(slots.len(), 16);
        assert_eq!(counts(&slots, 1), vec![16]);
    }

    #[test]
    fn slot_builder_distributes_prime_sum_weights() {
        let slots = build_slot_indices(&[5, 2]);
        assert_eq!(slots.len(), 16);
        // 5:2 ratio over 16 slots → 11:5 (nearest integer distribution)
        assert_eq!(counts(&slots, 2), vec![11, 5]);
    }
}
