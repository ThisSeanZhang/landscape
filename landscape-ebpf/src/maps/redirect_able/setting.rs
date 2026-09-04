use std::collections::HashMap;

use libbpf_rs::{MapCore, MapFlags};

use crate::MAP_PATHS;

pub fn set_xdp_redirect_able(ifindex: u32, able: bool) {
    let map = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.xdp_redirect_able) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!("open xdp_redirect_able map failed: {e}");
            return;
        }
    };

    let key = ifindex.to_ne_bytes();
    let value = u32::from(able).to_ne_bytes();
    if let Err(e) = map.update(&key, &value, MapFlags::ANY) {
        tracing::warn!("set xdp_redirect_able ifindex={ifindex} able={able} failed: {e}");
    }
}

pub fn del_xdp_redirect_able(ifindex: u32) {
    let map = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.xdp_redirect_able) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!("open xdp_redirect_able map failed: {e}");
            return;
        }
    };

    let key = ifindex.to_ne_bytes();
    if let Err(e) = map.delete(&key) {
        tracing::debug!("delete xdp_redirect_able ifindex={ifindex} failed: {e}");
    }
}

pub fn clear_xdp_redirect_able() {
    let map = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.xdp_redirect_able) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!("open xdp_redirect_able map failed: {e}");
            return;
        }
    };

    let keys: Vec<_> = map.keys().collect();
    for key in keys {
        if let Err(e) = map.delete(&key) {
            tracing::debug!("delete xdp_redirect_able key={key:?} failed: {e}");
        }
    }
}

pub fn is_xdp_redirect_able(ifindex: u32) -> bool {
    get_xdp_redirect_able(ifindex).unwrap_or(false)
}

pub fn get_xdp_redirect_able(ifindex: u32) -> Option<bool> {
    let map = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.xdp_redirect_able) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!("open xdp_redirect_able map failed: {e}");
            return None;
        }
    };

    let key = ifindex.to_ne_bytes();
    match map.lookup(&key, MapFlags::ANY) {
        Ok(Some(value)) => Some(
            value
                .get(..std::mem::size_of::<u32>())
                .and_then(|value| value.try_into().ok())
                .map(u32::from_ne_bytes)
                .unwrap_or(0)
                != 0,
        ),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("lookup xdp_redirect_able ifindex={ifindex} failed: {e}");
            None
        }
    }
}

pub fn batch_query_xdp_redirect_able(ifindexes: &[u32]) -> HashMap<u32, bool> {
    let map = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.xdp_redirect_able) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!("open xdp_redirect_able map failed: {e}");
            return HashMap::new();
        }
    };

    ifindexes
        .iter()
        .filter_map(|&ifindex| {
            let key = ifindex.to_ne_bytes();
            match map.lookup(&key, MapFlags::ANY) {
                Ok(Some(v)) => {
                    let val = v
                        .get(..std::mem::size_of::<u32>())
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_ne_bytes)
                        .unwrap_or(0);
                    Some((ifindex, val != 0))
                }
                _ => None,
            }
        })
        .collect()
}
