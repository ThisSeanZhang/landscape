use std::fs;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::time::Duration;

use landscape_common::net::MacAddr;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;
use tokio::sync::oneshot;

pub(crate) mod neigh_update {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/neigh_update.skel.rs"));
}

use neigh_update::*;

use crate::base::ip_mac::neigh_update::types::mac_key_v4;
use crate::base::ip_mac::neigh_update::types::mac_value_v4;
use crate::{bpf_error::LdEbpfResult, MAP_PATHS};

pub fn neigh_update(mut service_status: oneshot::Receiver<()>) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let builder = NeighUpdateSkelBuilder::default();

    // Use an Option to hold the link/skel to keep it alive during the loop if successful
    let _bpf_guard = match builder.open(&mut open_object) {
        Ok(mut open_skel) => {
            if let Err(e) = open_skel
                .maps
                .ip_mac_v4
                .set_pin_path(&MAP_PATHS.ip_mac_v4)
                .and_then(|_| open_skel.maps.ip_mac_v4.reuse_pinned_map(&MAP_PATHS.ip_mac_v4))
                .and_then(|_| open_skel.maps.ip_mac_v6.set_pin_path(&MAP_PATHS.ip_mac_v6))
                .and_then(|_| open_skel.maps.ip_mac_v6.reuse_pinned_map(&MAP_PATHS.ip_mac_v6))
            {
                tracing::warn!("Failed to setup maps for neigh_update: {:?}, fallback only.", e);
                None
            } else {
                match open_skel.load() {
                    Ok(skel) => {
                        match skel.progs.kprobe_neigh_update.attach_kprobe(false, "neigh_update") {
                            Ok(link) => Some((skel, link)),
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to attach neigh_update kprobe: {:?}, fallback only.",
                                    e
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load neigh_update skeleton (BTF missing?): {:?}, fallback only.", e);
                        None
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to open neigh_update skeleton: {:?}, fallback only.", e);
            None
        }
    };

    'm: loop {
        tracing::info!("syn curren arpv4 info");
        sync_arp_table_to_ebpf_map();

        for _ in 0..60 {
            if let Ok(_) | Err(oneshot::error::TryRecvError::Closed) = service_status.try_recv() {
                tracing::info!("neigh_update service stopping...");
                break 'm;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

pub fn sync_arp_table_to_ebpf_map() {
    let Ok(entries) = parse_arp_full_info() else {
        tracing::error!("read neigh error, maybe next time");
        return;
    };
    // tracing::info!("entries: {:?}", entries);

    if entries.is_empty() {
        return;
    }

    let ip_mac_v4 = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.ip_mac_v4).unwrap();

    let mut keys = vec![];
    let mut values = vec![];
    let count = entries.len() as u32;

    for (key, value) in entries {
        keys.extend_from_slice(unsafe { plain::as_bytes(&key) });
        values.extend_from_slice(unsafe { plain::as_bytes(&value) });
    }

    if let Err(e) = ip_mac_v4.update_batch(
        &keys,
        &values,
        count,
        libbpf_rs::MapFlags::ANY,
        libbpf_rs::MapFlags::ANY,
    ) {
        tracing::error!("update_batch error: {e:?}");
    }
}

fn parse_arp_full_info() -> Result<Vec<(mac_key_v4, mac_value_v4)>, std::io::Error> {
    let file = fs::File::open("/proc/net/arp")?;
    let reader = BufReader::new(file);
    let mut results = Vec::new();

    // 缓存网卡名对应的本地 MAC，避免重复读取同一个网卡的文件
    let mut dev_mac_cache = std::collections::HashMap::new();

    for line in reader.lines().skip(1) {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }

        let ip_str = fields[0];
        let neighbor_mac_str = fields[3];
        let dev_name = fields[5];

        if neighbor_mac_str == "00:00:00:00:00:00" {
            continue;
        }

        let ip_addr = ip_str.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        if ip_addr.is_unspecified() {
            continue;
        }

        let neighbor_mac = MacAddr::from_str(neighbor_mac_str).unwrap_or(MacAddr::zero());

        let ifindex = match nix::net::if_::if_nametoindex(dev_name) {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        let device_mac = if let Some(mac) = dev_mac_cache.get(dev_name) {
            *mac
        } else {
            let mac = get_device_mac(dev_name).unwrap_or(MacAddr::zero());
            // tracing::info!("read {dev_name:?} mac: {mac:?}");
            dev_mac_cache.insert(dev_name.to_string(), mac);
            mac
        };

        let mut key = mac_key_v4::default();
        let mut value = mac_value_v4::default();

        key.addr = ip_addr.to_bits().to_be();
        value.ifindex = ifindex;
        value.proto = 0x0008;
        value.mac = neighbor_mac.octets();
        value.dev_mac = device_mac.octets();

        results.push((key, value));
    }
    Ok(results)
}

fn get_device_mac(dev_name: &str) -> Option<MacAddr> {
    let path = format!("/sys/class/net/{}/address", dev_name);
    let mac_str = fs::read_to_string(path).ok()?;
    // tracing::info!("11 read {dev_name:?} mac: {mac_str:?}");
    MacAddr::from_str(&mac_str)
}
