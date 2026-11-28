//! Per-flow WAN target-slot maps (`rt4/6_target_slot_map`): weighted-slot
//! replacement/clear keyed by flow_id.

use std::collections::HashSet;
use std::net::IpAddr;

use landscape_common::config::FlowId;
use landscape_common::flow::FlowBalanceMode;
use landscape_common::sys_service::route_service::WanRouteTarget;
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::{FromBytes, IntoBytes};

use crate::maps::{
    LandscapeMapPath, Route4SlotKey, Route4TargetInfo, Route6SlotKey, Route6TargetInfo,
    RouteFlowTargetKey,
};
const FLOW_TARGET_SLOT_COUNT: usize = 256;
const ROUTE_BALANCE_DST_IP: u8 = 0;
const ROUTE_BALANCE_FIVE_TUPLE: u8 = 1;
pub(crate) const ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY: u32 = 256;

static RT_FLOW_MODE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn set_flow_balance_mode(paths: &LandscapeMapPath, flow_id: FlowId, mode: FlowBalanceMode) {
    if flow_id >= ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY {
        return;
    }
    let mode_map = match libbpf_rs::MapHandle::from_pinned_path(&paths.rt_flow_mode_map) {
        Ok(map) => map,
        Err(e) => {
            tracing::error!("open pinned rt_flow_mode_map error: {e:?}");
            return;
        }
    };
    set_flow_balance_mode_with_map(&mode_map, flow_id, mode);
}

pub(crate) fn set_flow_balance_mode_with_map<T: MapCore>(
    mode_map: &T,
    flow_id: FlowId,
    mode: FlowBalanceMode,
) {
    if flow_id >= ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY {
        return;
    }
    let _guard = RT_FLOW_MODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let raw_mode = match mode {
        FlowBalanceMode::DstIp => ROUTE_BALANCE_DST_IP,
        FlowBalanceMode::FiveTuple => ROUTE_BALANCE_FIVE_TUPLE,
    };
    if let Err(e) = mode_map.update(flow_id.as_bytes(), &[raw_mode], MapFlags::ANY) {
        tracing::error!("update rt_flow_mode_map for flow {flow_id} error: {e:?}");
        return;
    }
    let any_five_tuple = if raw_mode == ROUTE_BALANCE_FIVE_TUPLE {
        1u8
    } else {
        let mut active = 0u8;
        for id in 0..ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY {
            if let Ok(Some(bytes)) = mode_map.lookup(id.as_bytes(), MapFlags::ANY)
                && bytes.first().copied() == Some(ROUTE_BALANCE_FIVE_TUPLE)
            {
                active = 1;
                break;
            }
        }
        active
    };
    if let Err(e) = mode_map.update(
        ROUTE_FLOW_MODE_ANY_FIVE_TUPLE_KEY.as_bytes(),
        &[any_five_tuple],
        MapFlags::ANY,
    ) {
        tracing::error!("update rt_flow_mode_map summary error: {e:?}");
    }
}

pub fn replace_wan_route_slots_v4(
    paths: &LandscapeMapPath,
    flow_id: FlowId,
    targets: &[(WanRouteTarget, u32)],
) {
    let rt_target_map = libbpf_rs::MapHandle::from_pinned_path(&paths.rt4_slot_map).unwrap();
    let rt_flow_targets = libbpf_rs::MapHandle::from_pinned_path(&paths.rt4_flow_targets).unwrap();
    replace_wan_route_slots_v4_with_map(&rt_target_map, &rt_flow_targets, flow_id, targets);
}

pub fn replace_wan_route_slots_v6(
    paths: &LandscapeMapPath,
    flow_id: FlowId,
    targets: &[(WanRouteTarget, u32)],
) {
    let rt_target_map = libbpf_rs::MapHandle::from_pinned_path(&paths.rt6_slot_map).unwrap();
    let rt_flow_targets = libbpf_rs::MapHandle::from_pinned_path(&paths.rt6_flow_targets).unwrap();
    replace_wan_route_slots_v6_with_map(&rt_target_map, &rt_flow_targets, flow_id, targets);
}

pub fn del_wan_route_slots_v4(paths: &LandscapeMapPath, flow_id: FlowId) {
    let rt_target_map = libbpf_rs::MapHandle::from_pinned_path(&paths.rt4_slot_map).unwrap();
    let rt_flow_targets = libbpf_rs::MapHandle::from_pinned_path(&paths.rt4_flow_targets).unwrap();
    clear_wan_route_slots_v4(&rt_target_map, &rt_flow_targets, flow_id);
}

pub fn del_wan_route_slots_v6(paths: &LandscapeMapPath, flow_id: FlowId) {
    let rt_target_map = libbpf_rs::MapHandle::from_pinned_path(&paths.rt6_slot_map).unwrap();
    let rt_flow_targets = libbpf_rs::MapHandle::from_pinned_path(&paths.rt6_flow_targets).unwrap();
    clear_wan_route_slots_v6(&rt_target_map, &rt_flow_targets, flow_id);
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

fn build_target_info_v4(target: &WanRouteTarget) -> Route4TargetInfo {
    Route4TargetInfo {
        ifindex: target.info.ifindex,
        has_mac: u8::from(target.info.mac.is_some()),
        is_docker: u8::from(target.info.is_docker),
        link_chain_id: target.link_chain_id,
    }
}

fn build_target_info_v6(target: &WanRouteTarget) -> Route6TargetInfo {
    Route6TargetInfo {
        ifindex: target.info.ifindex,
        has_mac: u8::from(target.info.mac.is_some()),
        is_docker: u8::from(target.info.is_docker),
        link_chain_id: target.link_chain_id,
    }
}

fn clear_flow_targets_for_flow<U: MapCore>(rt_flow_targets: &U, flow_id: FlowId) {
    let stale_keys: Vec<Vec<u8>> = rt_flow_targets
        .keys()
        .filter(|key_bytes| {
            RouteFlowTargetKey::read_from_bytes(key_bytes)
                .map(|k| k.flow_id == flow_id)
                .unwrap_or(false)
        })
        .collect();

    for key_bytes in stale_keys {
        if let Err(e) = rt_flow_targets.delete(&key_bytes) {
            tracing::error!("delete stale flow_targets entry for flow {flow_id} error: {e:?}");
        }
    }
}

fn sync_flow_target_entries<U: MapCore, V: IntoBytes + zerocopy::Immutable>(
    rt_flow_targets: &U,
    flow_id: FlowId,
    filtered: &[&(WanRouteTarget, u32)],
    build_value: impl Fn(&WanRouteTarget) -> V,
    map_label: &str,
) {
    let active_ifindices: HashSet<u32> = filtered.iter().map(|(t, _)| t.info.ifindex).collect();
    let stale_keys: Vec<Vec<u8>> = rt_flow_targets
        .keys()
        .filter(|key_bytes| {
            RouteFlowTargetKey::read_from_bytes(key_bytes)
                .map(|k| k.flow_id == flow_id && !active_ifindices.contains(&k.ifindex))
                .unwrap_or(false)
        })
        .collect();
    for key_bytes in stale_keys {
        let _ = rt_flow_targets.delete(&key_bytes);
    }
    for (target, _) in filtered {
        let ft_key = RouteFlowTargetKey { flow_id, ifindex: target.info.ifindex };
        let ft_val = build_value(target);
        if let Err(e) = rt_flow_targets.update(ft_key.as_bytes(), ft_val.as_bytes(), MapFlags::ANY)
        {
            tracing::error!("upsert {map_label} error: {e:?}");
        }
    }
}

pub(crate) fn replace_wan_route_slots_v4_with_map<T, U>(
    rt_target_map: &T,
    rt_flow_targets: &U,
    flow_id: FlowId,
    targets: &[(WanRouteTarget, u32)],
) where
    T: MapCore,
    U: MapCore,
{
    let filtered: Vec<_> = targets
        .iter()
        .filter(|(target, weight)| *weight > 0 && matches!(target.info.gateway_ip, IpAddr::V4(_)))
        .collect();
    if filtered.is_empty() {
        clear_wan_route_slots_v4(rt_target_map, rt_flow_targets, flow_id);
        return;
    }

    sync_flow_target_entries(
        rt_flow_targets,
        flow_id,
        &filtered,
        build_target_info_v4,
        "rt4_flow_targets",
    );

    let weights: Vec<u32> = filtered.iter().map(|(_, weight)| *weight).collect();
    let slots = build_slot_indices(&weights);
    let slot_count = slots.len() as u32;
    let mut keys = Vec::with_capacity(slots.len() * std::mem::size_of::<Route4SlotKey>());
    let mut values = Vec::with_capacity(slots.len() * std::mem::size_of::<Route4TargetInfo>());

    for (slot, target_index) in slots.into_iter().enumerate() {
        let (target, _) = filtered[target_index];
        let key = Route4SlotKey { flow_id, slot: slot as u32 };
        let value = build_target_info_v4(target);

        keys.extend_from_slice(key.as_bytes());
        values.extend_from_slice(value.as_bytes());
    }

    if let Err(e) =
        rt_target_map.update_batch(&keys, &values, slot_count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("replace ipv4 wan slot batch error:{e:?}");
    }
}

pub(crate) fn replace_wan_route_slots_v6_with_map<T, U>(
    rt_target_map: &T,
    rt_flow_targets: &U,
    flow_id: FlowId,
    targets: &[(WanRouteTarget, u32)],
) where
    T: MapCore,
    U: MapCore,
{
    let filtered: Vec<_> = targets
        .iter()
        .filter(|(target, weight)| *weight > 0 && matches!(target.info.gateway_ip, IpAddr::V6(_)))
        .collect();
    if filtered.is_empty() {
        clear_wan_route_slots_v6(rt_target_map, rt_flow_targets, flow_id);
        return;
    }

    sync_flow_target_entries(
        rt_flow_targets,
        flow_id,
        &filtered,
        build_target_info_v6,
        "rt6_flow_targets",
    );

    let weights: Vec<u32> = filtered.iter().map(|(_, weight)| *weight).collect();
    let slots = build_slot_indices(&weights);
    let slot_count = slots.len() as u32;
    let mut keys = Vec::with_capacity(slots.len() * std::mem::size_of::<Route6SlotKey>());
    let mut values = Vec::with_capacity(slots.len() * std::mem::size_of::<Route6TargetInfo>());

    for (slot, target_index) in slots.into_iter().enumerate() {
        let (target, _) = filtered[target_index];
        let key = Route6SlotKey { flow_id, slot: slot as u32 };
        let value = build_target_info_v6(target);

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
fn clear_wan_route_slots_v4<T, U>(rt_target_map: &T, rt_flow_targets: &U, flow_id: FlowId)
where
    T: MapCore,
    U: MapCore,
{
    clear_flow_targets_for_flow(rt_flow_targets, flow_id);

    let mut keys =
        Vec::with_capacity(FLOW_TARGET_SLOT_COUNT * std::mem::size_of::<Route4SlotKey>());
    let mut count = 0;
    for slot in 0..FLOW_TARGET_SLOT_COUNT as u32 {
        let mut key = Route4SlotKey::default();
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

    if count > 0
        && let Err(e) = rt_target_map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("delete ipv4 wan slot batch error:{e:?}");
    }
}

#[allow(clippy::field_reassign_with_default)]
fn clear_wan_route_slots_v6<T, U>(rt_target_map: &T, rt_flow_targets: &U, flow_id: FlowId)
where
    T: MapCore,
    U: MapCore,
{
    clear_flow_targets_for_flow(rt_flow_targets, flow_id);

    let mut keys =
        Vec::with_capacity(FLOW_TARGET_SLOT_COUNT * std::mem::size_of::<Route6SlotKey>());
    let mut count = 0;
    for slot in 0..FLOW_TARGET_SLOT_COUNT as u32 {
        let mut key = Route6SlotKey::default();
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

    if count > 0
        && let Err(e) = rt_target_map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
    {
        tracing::error!("delete ipv6 wan slot batch error:{e:?}");
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
        assert_eq!(slots.len(), 256);
        assert_eq!(counts(&slots, 2), vec![128, 128]);
    }

    #[test]
    fn slot_builder_respects_three_to_one_ratio() {
        let slots = build_slot_indices(&[3, 1]);
        assert_eq!(slots.len(), 256);
        assert_eq!(counts(&slots, 2), vec![192, 64]);
    }

    #[test]
    fn slot_builder_skips_zero_weight_targets() {
        let slots = build_slot_indices(&[2, 0, 1]);
        assert_eq!(slots.len(), 256);
        assert_eq!(counts(&slots, 3), vec![171, 0, 85]);
    }

    #[test]
    fn slot_builder_fills_all_slots_for_single_target() {
        let slots = build_slot_indices(&[1]);
        assert_eq!(slots.len(), 256);
        assert_eq!(counts(&slots, 1), vec![256]);
    }

    #[test]
    fn slot_builder_distributes_prime_sum_weights() {
        let slots = build_slot_indices(&[5, 2]);
        assert_eq!(slots.len(), 256);
        // 5:2 ratio over 256 slots -> 183:73 (nearest integer distribution)
        assert_eq!(counts(&slots, 2), vec![183, 73]);
    }
}
