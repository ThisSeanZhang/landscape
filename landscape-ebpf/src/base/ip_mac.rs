use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use futures::stream::TryStreamExt;
use landscape_common::net::MacAddr;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{ErrorKind, MapCore, MapFlags, MapHandle};
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState};
use netlink_packet_route::AddressFamily;
use rtnetlink::IpVersion;
use tokio_util::sync::CancellationToken;

pub(crate) mod neigh_update {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/neigh_update.skel.rs"));
}

use neigh_update::*;

use crate::base::ip_mac::neigh_update::types::mac_key_v4;
use crate::base::ip_mac::neigh_update::types::mac_key_v6;
use crate::base::ip_mac::neigh_update::types::mac_value_v4;
use crate::base::ip_mac::neigh_update::types::mac_value_v6;
use crate::landscape::OwnedOpenObject;
use crate::{bpf_error::LdEbpfResult, landscape::pin_and_reuse_map, MAP_PATHS};

const ARP_SYNC_INTERVAL_SECS: u64 = 10;
const ETH_P_IPV4_BE: u16 = 0x0008;
const ETH_P_IPV6_BE: u16 = 0xdd86;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ArpSyncStats {
    deleted: usize,
    upserted: usize,
}

pub struct NeighUpdateHandle {
    _skel: NeighUpdateSkel<'static>,
    _backing: OwnedOpenObject,
    _link: Option<libbpf_rs::Link>,
}

pub fn init_neigh_update_handle() -> LdEbpfResult<NeighUpdateHandle> {
    let (backing, obj) = OwnedOpenObject::new();
    let builder = NeighUpdateSkelBuilder::default();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "neigh_update open skeleton failed")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
        "neigh_update prepare ip_mac_v4 failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
        "neigh_update prepare ip_mac_v6 failed"
    )?;

    let skel = crate::bpf_ctx!(open_skel.load(), "neigh_update load skeleton failed")?;

    let link = match skel.progs.kprobe_neigh_update.attach_kprobe(false, "neigh_update") {
        Ok(link) => Some(link),
        Err(e) => {
            tracing::warn!(
                "failed to attach neigh_update kprobe, falling back to periodic sync only: {e}"
            );
            None
        }
    };

    Ok(NeighUpdateHandle { _skel: skel, _backing: backing, _link: link })
}

pub async fn neigh_update(cancel: CancellationToken) -> LdEbpfResult<()> {
    let _handle = init_neigh_update_handle()?;

    let (connection, netlink_handle, _) = rtnetlink::new_connection()?;
    let conn_task = tokio::spawn(connection);

    loop {
        tracing::info!("sync current arp info");
        sync_arp_table_to_ebpf_map(&netlink_handle).await;

        tracing::info!("sync current ipv6 neigh info");
        sync_neigh_v6_table_to_ebpf_map(&netlink_handle).await;

        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("neigh_update service stopping...");
                conn_task.abort();
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_secs(ARP_SYNC_INTERVAL_SECS)) => {}
        }
    }
}

pub async fn sync_arp_table_to_ebpf_map(handle: &rtnetlink::Handle) {
    let entries = match parse_ipv4_neigh_full_info(handle).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!("read neigh error, skip current arp sync: {e}");
            return;
        }
    };

    let ip_mac_v4 = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.ip_mac_v4) {
        Ok(map) => map,
        Err(e) => {
            tracing::error!("open pinned ip_mac_v4 map error, skip current arp sync: {e}");
            return;
        }
    };

    match reconcile_arp_entries_in_map(&ip_mac_v4, &entries) {
        Ok(stats) => {
            tracing::debug!(
                "sync arpv4 info finished: deleted={}, upserted={}",
                stats.deleted,
                stats.upserted
            );
        }
        Err(e) => {
            tracing::error!("reconcile ip_mac_v4 map error: {e}");
        }
    }
}

pub async fn sync_neigh_v6_table_to_ebpf_map(handle: &rtnetlink::Handle) {
    let entries = match parse_ipv6_neigh_full_info(handle).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::error!("read ipv6 neigh error, skip current ipv6 neigh sync: {e}");
            return;
        }
    };

    let ip_mac_v6 = match libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.ip_mac_v6) {
        Ok(map) => map,
        Err(e) => {
            tracing::error!("open pinned ip_mac_v6 map error, skip current ipv6 neigh sync: {e}");
            return;
        }
    };

    match reconcile_ipv6_entries_in_map(&ip_mac_v6, &entries) {
        Ok(stats) => {
            tracing::debug!(
                "sync ipv6 neigh info finished: deleted={}, upserted={}",
                stats.deleted,
                stats.upserted
            );
        }
        Err(e) => {
            tracing::error!("reconcile ip_mac_v6 map error: {e}");
        }
    }
}

pub fn upsert_ipv4_ip_mac(
    ifindex: u32,
    ip_addr: Ipv4Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
) -> LdEbpfResult<()> {
    let ip_mac_v4 = MapHandle::from_pinned_path(&MAP_PATHS.ip_mac_v4)?;
    upsert_ipv4_ip_mac_in_map(&ip_mac_v4, ifindex, ip_addr, mac, dev_mac)
}

pub fn upsert_ipv6_ip_mac(
    ifindex: u32,
    ip_addr: Ipv6Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
) -> LdEbpfResult<()> {
    let ip_mac_v6 = MapHandle::from_pinned_path(&MAP_PATHS.ip_mac_v6)?;
    upsert_ipv6_ip_mac_in_map(&ip_mac_v6, ifindex, ip_addr, mac, dev_mac)
}

fn upsert_ipv4_ip_mac_in_map<T>(
    map: &T,
    ifindex: u32,
    ip_addr: Ipv4Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
) -> LdEbpfResult<()>
where
    T: MapCore,
{
    let mut key = mac_key_v4::default();
    key.addr = ip_addr.to_bits().to_be();

    let mut value = mac_value_v4::default();
    value.ifindex = ifindex;
    value.proto = ETH_P_IPV4_BE;
    value.mac = mac.octets();
    value.dev_mac = dev_mac.octets();

    map.update(
        unsafe { plain::as_bytes(&key) },
        unsafe { plain::as_bytes(&value) },
        MapFlags::ANY,
    )?;
    Ok(())
}

fn upsert_ipv6_ip_mac_in_map<T>(
    map: &T,
    ifindex: u32,
    ip_addr: Ipv6Addr,
    mac: MacAddr,
    dev_mac: MacAddr,
) -> LdEbpfResult<()>
where
    T: MapCore,
{
    let mut key = mac_key_v6::default();
    key.addr.bytes = ip_addr.to_bits().to_be_bytes();

    let mut value = mac_value_v6::default();
    value.ifindex = ifindex;
    value.proto = ETH_P_IPV6_BE;
    value.mac = mac.octets();
    value.dev_mac = dev_mac.octets();

    map.update(
        unsafe { plain::as_bytes(&key) },
        unsafe { plain::as_bytes(&value) },
        MapFlags::ANY,
    )?;
    Ok(())
}

fn reconcile_arp_entries_in_map<T>(
    map: &T,
    entries: &[(mac_key_v4, mac_value_v4)],
) -> libbpf_rs::Result<ArpSyncStats>
where
    T: MapCore,
{
    let desired_addrs: HashSet<u32> = entries.iter().map(|(key, _)| key.addr).collect();
    let mut stale_keys = Vec::new();

    for raw_key in map.keys() {
        let raw_key = read_unaligned::<mac_key_v4>(&raw_key).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decode ip_mac_v4 key failed: invalid key size {}", raw_key.len()),
            )
        })?;

        if !desired_addrs.contains(&raw_key.addr) {
            let mut stale_key = mac_key_v4::default();
            stale_key.addr = raw_key.addr;
            stale_keys.push(stale_key);
        }
    }

    for key in &stale_keys {
        if let Err(e) = map.delete(unsafe { plain::as_bytes(key) }) {
            if e.kind() != ErrorKind::NotFound {
                return Err(e);
            }
        }
    }

    if !entries.is_empty() {
        let (keys, values) = build_batch_buffers(entries);
        map.update_batch(&keys, &values, entries.len() as u32, MapFlags::ANY, MapFlags::ANY)?;
    }

    Ok(ArpSyncStats { deleted: stale_keys.len(), upserted: entries.len() })
}

fn reconcile_ipv6_entries_in_map<T>(
    map: &T,
    entries: &[(mac_key_v6, mac_value_v6)],
) -> libbpf_rs::Result<ArpSyncStats>
where
    T: MapCore,
{
    let desired_addrs: HashSet<[u8; 16]> =
        entries.iter().map(|(key, _)| unsafe { key.addr.bytes }).collect();
    let mut stale_keys = Vec::new();

    for raw_key in map.keys() {
        let raw_key = read_unaligned::<mac_key_v6>(&raw_key).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decode ip_mac_v6 key failed: invalid key size {}", raw_key.len()),
            )
        })?;

        let addr_bytes = unsafe { raw_key.addr.bytes };
        if !desired_addrs.contains(&addr_bytes) {
            stale_keys.push(raw_key);
        }
    }

    for key in &stale_keys {
        if let Err(e) = map.delete(unsafe { plain::as_bytes(key) }) {
            if e.kind() != ErrorKind::NotFound {
                return Err(e);
            }
        }
    }

    if !entries.is_empty() {
        let (keys, values) = build_batch_buffers_v6(entries);
        map.update_batch(&keys, &values, entries.len() as u32, MapFlags::ANY, MapFlags::ANY)?;
    }

    Ok(ArpSyncStats { deleted: stale_keys.len(), upserted: entries.len() })
}

fn build_batch_buffers(entries: &[(mac_key_v4, mac_value_v4)]) -> (Vec<u8>, Vec<u8>) {
    let mut keys = Vec::with_capacity(entries.len() * std::mem::size_of::<mac_key_v4>());
    let mut values = Vec::with_capacity(entries.len() * std::mem::size_of::<mac_value_v4>());

    for (key, value) in entries {
        keys.extend_from_slice(unsafe { plain::as_bytes(key) });
        values.extend_from_slice(unsafe { plain::as_bytes(value) });
    }

    (keys, values)
}

fn build_batch_buffers_v6(entries: &[(mac_key_v6, mac_value_v6)]) -> (Vec<u8>, Vec<u8>) {
    let mut keys = Vec::with_capacity(entries.len() * std::mem::size_of::<mac_key_v6>());
    let mut values = Vec::with_capacity(entries.len() * std::mem::size_of::<mac_value_v6>());

    for (key, value) in entries {
        keys.extend_from_slice(unsafe { plain::as_bytes(key) });
        values.extend_from_slice(unsafe { plain::as_bytes(value) });
    }

    (keys, values)
}

fn read_unaligned<T>(bytes: &[u8]) -> Option<T>
where
    T: Copy,
{
    if bytes.len() != std::mem::size_of::<T>() {
        return None;
    }

    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

async fn parse_ipv6_neigh_full_info(
    handle: &rtnetlink::Handle,
) -> Result<Vec<(mac_key_v6, mac_value_v6)>, std::io::Error> {
    let mut results = Vec::new();
    let mut dev_mac_cache = std::collections::HashMap::new();

    let mut stream = handle.neighbours().get().set_family(IpVersion::V6).execute();

    loop {
        let msg = match stream.try_next().await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("netlink error: {e}"),
                ));
            }
        };

        if msg.header.family != AddressFamily::Inet6 {
            continue;
        }

        if let Some(entry) = ipv6_neigh_msg_to_entry(&msg, &mut dev_mac_cache) {
            results.push(entry);
        }
    }

    Ok(results)
}

async fn parse_ipv4_neigh_full_info(
    handle: &rtnetlink::Handle,
) -> Result<Vec<(mac_key_v4, mac_value_v4)>, std::io::Error> {
    let mut results = Vec::new();
    let mut dev_mac_cache = std::collections::HashMap::new();

    let mut stream = handle.neighbours().get().set_family(IpVersion::V4).execute();

    loop {
        let msg = match stream.try_next().await {
            Ok(Some(msg)) => msg,
            Ok(None) => break,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("netlink error: {e}"),
                ));
            }
        };

        if msg.header.family != AddressFamily::Inet {
            continue;
        }

        if let Some(entry) = ipv4_neigh_msg_to_entry(&msg, &mut dev_mac_cache) {
            results.push(entry);
        }
    }

    Ok(results)
}

fn ipv4_neigh_msg_to_entry(
    msg: &netlink_packet_route::neighbour::NeighbourMessage,
    dev_mac_cache: &mut std::collections::HashMap<String, MacAddr>,
) -> Option<(mac_key_v4, mac_value_v4)> {
    match msg.header.state {
        NeighbourState::Failed
        | NeighbourState::Incomplete
        | NeighbourState::Noarp
        | NeighbourState::None => return None,
        _ => {}
    }

    let mut ipv4_addr = None;
    let mut mac_bytes: Option<Vec<u8>> = None;

    for attr in &msg.attributes {
        match attr {
            NeighbourAttribute::Destination(addr) => {
                if let NeighbourAddress::Inet(ip) = addr {
                    ipv4_addr = Some(*ip);
                }
            }
            NeighbourAttribute::LinkLayerAddress(bytes) => {
                if bytes.len() >= 6 && !bytes.iter().all(|&b| b == 0) {
                    mac_bytes = Some(bytes.clone());
                }
            }
            _ => {}
        }
    }

    let ip_addr = match ipv4_addr {
        Some(ip) if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() => ip,
        _ => return None,
    };

    let neighbor_mac = match mac_bytes.as_deref() {
        Some(bytes) => match MacAddr::from_arry(bytes) {
            Some(mac) => mac,
            None => return None,
        },
        None => return None,
    };

    let ifindex = msg.header.ifindex;

    let device_mac = {
        let dev_name = match nix::net::if_::if_indextoname(ifindex) {
            Ok(cs) => match cs.into_string() {
                Ok(s) => s,
                Err(_) => return None,
            },
            Err(_) => return None,
        };

        if let Some(mac) = dev_mac_cache.get(&dev_name) {
            *mac
        } else {
            let mac = get_device_mac(&dev_name).unwrap_or(MacAddr::zero());
            dev_mac_cache.insert(dev_name, mac);
            mac
        }
    };

    let mut key = mac_key_v4::default();
    let mut value = mac_value_v4::default();

    key.addr = ip_addr.to_bits().to_be();
    value.ifindex = ifindex;
    value.proto = ETH_P_IPV4_BE;
    value.mac = neighbor_mac.octets();
    value.dev_mac = device_mac.octets();

    Some((key, value))
}

fn ipv6_neigh_msg_to_entry(
    msg: &netlink_packet_route::neighbour::NeighbourMessage,
    dev_mac_cache: &mut std::collections::HashMap<String, MacAddr>,
) -> Option<(mac_key_v6, mac_value_v6)> {
    match msg.header.state {
        NeighbourState::Failed
        | NeighbourState::Incomplete
        | NeighbourState::Noarp
        | NeighbourState::None => return None,
        _ => {}
    }

    let mut ipv6_addr = None;
    let mut mac_bytes: Option<Vec<u8>> = None;

    for attr in &msg.attributes {
        match attr {
            NeighbourAttribute::Destination(addr) => {
                if let NeighbourAddress::Inet6(ip) = addr {
                    ipv6_addr = Some(*ip);
                }
            }
            NeighbourAttribute::LinkLayerAddress(bytes) => {
                if bytes.len() >= 6 && !bytes.iter().all(|&b| b == 0) {
                    mac_bytes = Some(bytes.clone());
                }
            }
            _ => {}
        }
    }

    let ip_addr = match ipv6_addr {
        Some(ip) if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() => ip,
        _ => return None,
    };

    let neighbor_mac = match mac_bytes.as_deref() {
        Some(bytes) => match MacAddr::from_arry(bytes) {
            Some(mac) => mac,
            None => return None,
        },
        None => return None,
    };

    let ifindex = msg.header.ifindex;

    let device_mac = {
        let dev_name = match nix::net::if_::if_indextoname(ifindex) {
            Ok(cs) => match cs.into_string() {
                Ok(s) => s,
                Err(_) => return None,
            },
            Err(_) => return None,
        };

        if let Some(mac) = dev_mac_cache.get(&dev_name) {
            *mac
        } else {
            let mac = get_device_mac(&dev_name).unwrap_or(MacAddr::zero());
            dev_mac_cache.insert(dev_name, mac);
            mac
        }
    };

    let mut key = mac_key_v6::default();
    let mut value = mac_value_v6::default();

    key.addr.bytes = ip_addr.to_bits().to_be_bytes();
    value.ifindex = ifindex;
    value.proto = ETH_P_IPV6_BE;
    value.mac = neighbor_mac.octets();
    value.dev_mac = device_mac.octets();

    Some((key, value))
}

fn get_device_mac(dev_name: &str) -> Option<MacAddr> {
    let path = format!("/sys/class/net/{}/address", dev_name);
    let mac_str = fs::read_to_string(path).ok()?;
    MacAddr::from_str(&mac_str)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use libbpf_rs::{libbpf_sys, MapHandle, MapType};

    use super::*;

    fn create_test_ip_mac_map() -> MapHandle {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        MapHandle::create(
            MapType::Hash,
            Option::<&str>::None,
            std::mem::size_of::<mac_key_v4>() as u32,
            std::mem::size_of::<mac_value_v4>() as u32,
            128,
            &opts,
        )
        .expect("create ip_mac test map")
    }

    fn create_test_ip_mac_v6_map() -> MapHandle {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };

        MapHandle::create(
            MapType::Hash,
            Option::<&str>::None,
            std::mem::size_of::<mac_key_v6>() as u32,
            std::mem::size_of::<mac_value_v6>() as u32,
            128,
            &opts,
        )
        .expect("create ip_mac_v6 test map")
    }

    fn make_entry(ip: &str, mac: &str, dev_mac: &str, ifindex: u32) -> (mac_key_v4, mac_value_v4) {
        let mut key = mac_key_v4::default();
        key.addr = Ipv4Addr::from_str(ip).unwrap().to_bits().to_be();

        let mut value = mac_value_v4::default();
        value.ifindex = ifindex;
        value.mac = MacAddr::from_str(mac).unwrap().octets();
        value.dev_mac = MacAddr::from_str(dev_mac).unwrap().octets();
        value.proto = ETH_P_IPV4_BE;

        (key, value)
    }

    fn make_entry_v6(
        ip: &str,
        mac: &str,
        dev_mac: &str,
        ifindex: u32,
    ) -> (mac_key_v6, mac_value_v6) {
        let mut key = mac_key_v6::default();
        key.addr.bytes = std::net::Ipv6Addr::from_str(ip).unwrap().to_bits().to_be_bytes();

        let mut value = mac_value_v6::default();
        value.ifindex = ifindex;
        value.mac = MacAddr::from_str(mac).unwrap().octets();
        value.dev_mac = MacAddr::from_str(dev_mac).unwrap().octets();
        value.proto = ETH_P_IPV6_BE;

        (key, value)
    }

    fn insert_entry<T>(map: &T, entry: &(mac_key_v4, mac_value_v4))
    where
        T: MapCore,
    {
        map.update(
            unsafe { plain::as_bytes(&entry.0) },
            unsafe { plain::as_bytes(&entry.1) },
            MapFlags::ANY,
        )
        .expect("insert ip_mac entry");
    }

    fn insert_entry_v6<T>(map: &T, entry: &(mac_key_v6, mac_value_v6))
    where
        T: MapCore,
    {
        map.update(
            unsafe { plain::as_bytes(&entry.0) },
            unsafe { plain::as_bytes(&entry.1) },
            MapFlags::ANY,
        )
        .expect("insert ip_mac_v6 entry");
    }

    fn lookup_entry<T>(map: &T, ip: &str) -> Option<mac_value_v4>
    where
        T: MapCore,
    {
        let mut key = mac_key_v4::default();
        key.addr = Ipv4Addr::from_str(ip).unwrap().to_bits().to_be();

        map.lookup(unsafe { plain::as_bytes(&key) }, MapFlags::ANY)
            .expect("lookup ip_mac entry")
            .map(|value| read_unaligned::<mac_value_v4>(&value).expect("decode ip_mac entry"))
    }

    fn lookup_entry_v6<T>(map: &T, ip: &str) -> Option<mac_value_v6>
    where
        T: MapCore,
    {
        let mut key = mac_key_v6::default();
        key.addr.bytes = std::net::Ipv6Addr::from_str(ip).unwrap().to_bits().to_be_bytes();

        map.lookup(unsafe { plain::as_bytes(&key) }, MapFlags::ANY)
            .expect("lookup ip_mac_v6 entry")
            .map(|value| read_unaligned::<mac_value_v6>(&value).expect("decode ip_mac_v6 entry"))
    }

    #[test]
    fn upsert_ipv4_ip_mac_in_map_stores_client_and_device_mac() {
        let map = create_test_ip_mac_map();
        let client_mac = MacAddr::from_str("02:11:22:33:44:55").unwrap();
        let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();

        upsert_ipv4_ip_mac_in_map(&map, 9, Ipv4Addr::new(10, 0, 0, 8), client_mac, dev_mac)
            .expect("upsert ipv4 ip_mac entry");

        let stored = lookup_entry(&map, "10.0.0.8").expect("entry missing after ipv4 upsert");
        assert_eq!(stored.ifindex, 9);
        assert_eq!(stored.mac, client_mac.octets());
        assert_eq!(stored.dev_mac, dev_mac.octets());
        assert_eq!(stored.proto, ETH_P_IPV4_BE);
    }

    #[test]
    fn upsert_ipv6_ip_mac_in_map_stores_client_and_device_mac() {
        let map = create_test_ip_mac_v6_map();
        let client_mac = MacAddr::from_str("02:66:77:88:99:aa").unwrap();
        let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ef").unwrap();

        upsert_ipv6_ip_mac_in_map(
            &map,
            11,
            std::net::Ipv6Addr::from_str("2001:db8::20").unwrap(),
            client_mac,
            dev_mac,
        )
        .expect("upsert ipv6 ip_mac entry");

        let stored =
            lookup_entry_v6(&map, "2001:db8::20").expect("entry missing after ipv6 upsert");
        assert_eq!(stored.ifindex, 11);
        assert_eq!(stored.mac, client_mac.octets());
        assert_eq!(stored.dev_mac, dev_mac.octets());
        assert_eq!(stored.proto, ETH_P_IPV6_BE);
    }

    #[test]
    fn reconcile_updates_existing_ip_mac_entry() {
        let map = create_test_ip_mac_map();
        let original = make_entry("10.0.0.8", "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee", 7);
        insert_entry(&map, &original);

        let updated = make_entry("10.0.0.8", "02:66:77:88:99:aa", "02:aa:bb:cc:dd:ee", 9);
        let stats = reconcile_arp_entries_in_map(&map, &[updated]).expect("reconcile ip_mac map");

        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.upserted, 1);
        let stored = lookup_entry(&map, "10.0.0.8").expect("entry missing after update");
        assert_eq!(stored.ifindex, 9);
        assert_eq!(stored.mac, updated.1.mac);
    }

    #[test]
    fn reconcile_deletes_stale_ip_mac_entries() {
        let map = create_test_ip_mac_map();
        let keep = make_entry("10.0.0.8", "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee", 7);
        let stale = make_entry("10.0.0.9", "02:66:77:88:99:aa", "02:aa:bb:cc:dd:ef", 8);
        insert_entry(&map, &keep);
        insert_entry(&map, &stale);

        let stats = reconcile_arp_entries_in_map(&map, &[keep]).expect("reconcile ip_mac map");

        assert_eq!(stats.deleted, 1);
        assert_eq!(lookup_entry(&map, "10.0.0.8").unwrap().mac, keep.1.mac);
        assert!(lookup_entry(&map, "10.0.0.9").is_none());
    }

    #[test]
    fn reconcile_clears_map_when_arp_snapshot_is_empty() {
        let map = create_test_ip_mac_map();
        let first = make_entry("10.0.0.8", "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee", 7);
        let second = make_entry("10.0.0.9", "02:66:77:88:99:aa", "02:aa:bb:cc:dd:ef", 8);
        insert_entry(&map, &first);
        insert_entry(&map, &second);

        let stats = reconcile_arp_entries_in_map(&map, &[]).expect("reconcile ip_mac map");

        assert_eq!(stats.deleted, 2);
        assert_eq!(stats.upserted, 0);
        assert_eq!(map.keys().count(), 0);
    }

    #[test]
    fn reconcile_v6_updates_existing_entry() {
        let map = create_test_ip_mac_v6_map();
        let original = make_entry_v6("2001:db8::8", "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee", 7);
        insert_entry_v6(&map, &original);

        let updated = make_entry_v6("2001:db8::8", "02:66:77:88:99:aa", "02:aa:bb:cc:dd:ee", 9);
        let stats =
            reconcile_ipv6_entries_in_map(&map, &[updated]).expect("reconcile ip_mac_v6 map");

        assert_eq!(stats.deleted, 0);
        assert_eq!(stats.upserted, 1);
        let stored = lookup_entry_v6(&map, "2001:db8::8").expect("entry missing after update");
        assert_eq!(stored.ifindex, 9);
        assert_eq!(stored.mac, updated.1.mac);
    }

    #[test]
    fn reconcile_v6_deletes_stale_entries() {
        let map = create_test_ip_mac_v6_map();
        let keep = make_entry_v6("2001:db8::8", "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee", 7);
        let stale = make_entry_v6("2001:db8::9", "02:66:77:88:99:aa", "02:aa:bb:cc:dd:ef", 8);
        insert_entry_v6(&map, &keep);
        insert_entry_v6(&map, &stale);

        let stats = reconcile_ipv6_entries_in_map(&map, &[keep]).expect("reconcile ip_mac_v6 map");

        assert_eq!(stats.deleted, 1);
        assert_eq!(lookup_entry_v6(&map, "2001:db8::8").unwrap().mac, keep.1.mac);
        assert!(lookup_entry_v6(&map, "2001:db8::9").is_none());
    }

    #[test]
    fn reconcile_v6_clears_map_when_snapshot_is_empty() {
        let map = create_test_ip_mac_v6_map();
        let first = make_entry_v6("2001:db8::8", "02:11:22:33:44:55", "02:aa:bb:cc:dd:ee", 7);
        let second = make_entry_v6("2001:db8::9", "02:66:77:88:99:aa", "02:aa:bb:cc:dd:ef", 8);
        insert_entry_v6(&map, &first);
        insert_entry_v6(&map, &second);

        let stats = reconcile_ipv6_entries_in_map(&map, &[]).expect("reconcile ip_mac_v6 map");

        assert_eq!(stats.deleted, 2);
        assert_eq!(stats.upserted, 0);
        assert_eq!(map.keys().count(), 0);
    }

    #[test]
    fn ipv4_neigh_msg_to_entry_extracts_fields() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut msg = NeighbourMessage::default();
        msg.header = NeighbourHeader {
            family: AddressFamily::Inet,
            ifindex: 1,
            state: NeighbourState::Reachable,
            ..Default::default()
        };
        msg.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet(Ipv4Addr::new(10, 0, 0, 1))),
            NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];

        let mut cache = std::collections::HashMap::new();
        // ifindex=1 is typically "lo" on Linux
        let dev_name = nix::net::if_::if_indextoname(1)
            .expect("if_indextoname(1) should succeed")
            .into_string()
            .expect("interface name should be valid UTF-8");
        let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
        cache.insert(dev_name, dev_mac);

        let (key, value) = ipv4_neigh_msg_to_entry(&msg, &mut cache)
            .expect("valid reachable neighbour should produce an entry");

        assert_eq!(value.ifindex, 1);
        assert_eq!(value.mac, MacAddr::from_str("02:11:22:33:44:55").unwrap().octets());
        assert_eq!(value.dev_mac, dev_mac.octets());
        assert_eq!(value.proto, ETH_P_IPV4_BE);
        assert_eq!(key.addr, Ipv4Addr::new(10, 0, 0, 1).to_bits().to_be());
    }

    #[test]
    fn ipv4_neigh_msg_filters_invalid_states() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut cache = std::collections::HashMap::new();

        let make_msg = |state| {
            let mut m = NeighbourMessage::default();
            m.header = NeighbourHeader {
                family: AddressFamily::Inet,
                ifindex: 0,
                state,
                ..Default::default()
            };
            m.attributes = vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet(Ipv4Addr::new(10, 0, 0, 1))),
                NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ];
            m
        };

        for state in [
            NeighbourState::Failed,
            NeighbourState::Incomplete,
            NeighbourState::Noarp,
            NeighbourState::None,
        ] {
            assert!(
                ipv4_neigh_msg_to_entry(&make_msg(state), &mut cache).is_none(),
                "state {:?} should be filtered out",
                state
            );
        }
    }

    #[test]
    fn ipv4_neigh_msg_filters_unspecified_loopback_multicast() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut cache = std::collections::HashMap::new();

        let make_msg = |ip| {
            let mut m = NeighbourMessage::default();
            m.header = NeighbourHeader {
                family: AddressFamily::Inet,
                ifindex: 0,
                state: NeighbourState::Reachable,
                ..Default::default()
            };
            m.attributes = vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)),
                NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ];
            m
        };

        assert!(ipv4_neigh_msg_to_entry(&make_msg(Ipv4Addr::UNSPECIFIED), &mut cache).is_none());
        assert!(
            ipv4_neigh_msg_to_entry(&make_msg(Ipv4Addr::new(127, 0, 0, 1)), &mut cache).is_none()
        );
        assert!(
            ipv4_neigh_msg_to_entry(&make_msg(Ipv4Addr::new(224, 0, 0, 1)), &mut cache).is_none()
        );
    }

    #[test]
    fn ipv6_neigh_msg_to_entry_extracts_fields() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut msg = NeighbourMessage::default();
        msg.header = NeighbourHeader {
            family: AddressFamily::Inet6,
            ifindex: 1,
            state: NeighbourState::Reachable,
            ..Default::default()
        };
        msg.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                Ipv6Addr::from_str("2001:db8::1").unwrap(),
            )),
            NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];

        let mut cache = std::collections::HashMap::new();
        let dev_name = nix::net::if_::if_indextoname(1)
            .expect("if_indextoname(1) should succeed")
            .into_string()
            .expect("interface name should be valid UTF-8");
        let dev_mac = MacAddr::from_str("02:aa:bb:cc:dd:ee").unwrap();
        cache.insert(dev_name, dev_mac);

        let (key, value) = ipv6_neigh_msg_to_entry(&msg, &mut cache)
            .expect("valid reachable neighbour should produce an entry");

        assert_eq!(value.ifindex, 1);
        assert_eq!(value.mac, MacAddr::from_str("02:11:22:33:44:55").unwrap().octets());
        assert_eq!(value.dev_mac, dev_mac.octets());
        assert_eq!(value.proto, ETH_P_IPV6_BE);
        assert_eq!(
            unsafe { key.addr.bytes },
            Ipv6Addr::from_str("2001:db8::1").unwrap().to_bits().to_be_bytes()
        );
    }

    #[test]
    fn ipv6_neigh_msg_to_entry_filters_invalid_states() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut cache = std::collections::HashMap::new();

        let make_msg = |state| {
            let mut m = NeighbourMessage::default();
            m.header = NeighbourHeader {
                family: AddressFamily::Inet6,
                ifindex: 0,
                state,
                ..Default::default()
            };
            m.attributes = vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(
                    Ipv6Addr::from_str("2001:db8::1").unwrap(),
                )),
                NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ];
            m
        };

        for state in [
            NeighbourState::Failed,
            NeighbourState::Incomplete,
            NeighbourState::Noarp,
            NeighbourState::None,
        ] {
            assert!(
                ipv6_neigh_msg_to_entry(&make_msg(state), &mut cache).is_none(),
                "state {:?} should be filtered out",
                state
            );
        }
    }

    #[test]
    fn ipv6_neigh_msg_to_entry_filters_unspecified() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut cache = std::collections::HashMap::new();

        let mut m = NeighbourMessage::default();
        m.header = NeighbourHeader {
            family: AddressFamily::Inet6,
            ifindex: 0,
            state: NeighbourState::Reachable,
            ..Default::default()
        };
        m.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(Ipv6Addr::UNSPECIFIED)),
            NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];

        assert!(ipv6_neigh_msg_to_entry(&m, &mut cache).is_none());
    }

    #[test]
    fn ipv6_neigh_msg_filters_loopback_multicast() {
        use netlink_packet_route::neighbour::{NeighbourHeader, NeighbourMessage};

        let mut cache = std::collections::HashMap::new();

        let make_msg = |ip| {
            let mut m = NeighbourMessage::default();
            m.header = NeighbourHeader {
                family: AddressFamily::Inet6,
                ifindex: 0,
                state: NeighbourState::Reachable,
                ..Default::default()
            };
            m.attributes = vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip)),
                NeighbourAttribute::LinkLayerAddress(vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            ];
            m
        };

        assert!(
            ipv6_neigh_msg_to_entry(&make_msg(Ipv6Addr::from_str("::1").unwrap()), &mut cache,)
                .is_none()
        );
        assert!(ipv6_neigh_msg_to_entry(
            &make_msg(Ipv6Addr::from_str("ff02::1").unwrap()),
            &mut cache,
        )
        .is_none());
    }

    #[test]
    fn get_device_mac_returns_some_for_existing_interface() {
        let mac = get_device_mac("lo");
        assert!(mac.is_some(), "should return MAC for loopback interface");
    }
}
