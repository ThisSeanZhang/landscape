use std::{
    os::fd::{AsFd, AsRawFd},
    time::Instant,
};

use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};

use crate::{
    map_setting::share_map::types::{net_metric_key, net_metric_value},
    MAP_PATHS,
};

const METRIC_MAX_ENTRIES: u32 = 2048;

pub fn create_metric_inner_map(second: u32) {
    let now = Instant::now();
    #[allow(clippy::needless_update)]
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
        ..Default::default()
    };

    let key_size = size_of::<net_metric_key>() as u32;
    let value_size = size_of::<net_metric_value>() as u32;

    let map = MapHandle::create(
        MapType::PercpuHash,
        Some(format!("metric_{}", second)),
        key_size,
        value_size,
        METRIC_MAX_ENTRIES,
        &opts,
    )
    .unwrap();
    let time = now.elapsed().as_nanos();
    tracing::debug!("create map elapsed: {time} nanos");

    let now = Instant::now();
    let map_fd = map.as_fd().as_raw_fd();
    let flow_dns_match_map = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.metric_map).unwrap();

    let key = second;
    let key_value = unsafe { plain::as_bytes(&key) };

    let value_value = unsafe { plain::as_bytes(&map_fd) };

    if let Err(e) = flow_dns_match_map.update(key_value, value_value, MapFlags::ANY) {
        let last_os_error = std::io::Error::last_os_error();
        tracing::error!("Last OS error: {:?}", last_os_error);
        tracing::error!("Last OS error: {e:?}");
    }

    let time = now.elapsed().as_nanos();
    tracing::debug!("insert map elapsed: {time} nanos");
}
