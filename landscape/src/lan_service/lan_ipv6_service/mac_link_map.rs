use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::stream::TryStreamExt;
use landscape_common::net::MacAddr;
use netlink_packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourState};
use netlink_packet_route::AddressFamily;
use rtnetlink::{Handle, IpVersion};

struct MacLinkMap {
    mac_to_ll: HashMap<(u32, MacAddr), Ipv6Addr>,
    ll_to_mac: HashMap<(u32, Ipv6Addr), MacAddr>,
}

impl MacLinkMap {
    fn new() -> Self {
        MacLinkMap {
            mac_to_ll: HashMap::new(),
            ll_to_mac: HashMap::new(),
        }
    }

    fn record(&mut self, ifindex: u32, mac: MacAddr, ll: Ipv6Addr) {
        if let Some(old_ll) = self.mac_to_ll.insert((ifindex, mac), ll) {
            self.ll_to_mac.remove(&(ifindex, old_ll));
        }
        if let Some(old_mac) = self.ll_to_mac.insert((ifindex, ll), mac) {
            self.mac_to_ll.remove(&(ifindex, old_mac));
        }
    }

    fn lookup_ll_by_mac(&self, ifindex: u32, mac: &MacAddr) -> Option<Ipv6Addr> {
        self.mac_to_ll.get(&(ifindex, *mac)).copied()
    }

    fn lookup_mac_by_ll(&self, ifindex: u32, ll: &Ipv6Addr) -> Option<MacAddr> {
        self.ll_to_mac.get(&(ifindex, *ll)).copied()
    }
}

pub struct MacLinkMapCache {
    inner: RwLock<MacLinkMap>,
}

impl MacLinkMapCache {
    pub fn new() -> Self {
        MacLinkMapCache { inner: RwLock::new(MacLinkMap::new()) }
    }

    pub fn record(&self, ifindex: u32, mac: MacAddr, ll: Ipv6Addr) {
        self.inner.write().unwrap().record(ifindex, mac, ll);
    }

    pub fn lookup_ll_by_mac(&self, ifindex: u32, mac: &MacAddr) -> Option<Ipv6Addr> {
        self.inner.read().unwrap().lookup_ll_by_mac(ifindex, mac)
    }

    pub fn lookup_mac_by_ll(&self, ifindex: u32, ll: &Ipv6Addr) -> Option<MacAddr> {
        self.inner.read().unwrap().lookup_mac_by_ll(ifindex, ll)
    }
}

/// Start a background task that periodically dumps the kernel's IPv6 neighbour
/// table and populates `cache`.  Each interval, all reachable-ish link-local
/// neighbour entries are recorded so the cache stays fresh even when no NA
/// messages have been received.
///
/// The rtnetlink connection is created internally and re-established on error
/// with exponential backoff.
pub fn start_periodic_scan(cache: &Arc<MacLinkMapCache>, interval_secs: u64) {
    let cache = cache.clone();
    tokio::spawn(async move {
        let mut retry = Duration::from_secs(1);

        loop {
            // ── Create a new rtnetlink connection ──
            let (connection, handle, _) = match rtnetlink::new_connection() {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("rtnetlink new_connection failed: {e}, retry in {retry:?}");
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(Duration::from_secs(60));
                    continue;
                }
            };
            tokio::spawn(connection);
            retry = Duration::from_secs(1);

            // ── Scan loop for this connection ──
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.tick().await; // skip the immediate first tick

            loop {
                interval.tick().await;
                if let Err(e) = scan_once(&cache, &handle).await {
                    tracing::warn!("neigh scan failed: {e}, reconnecting...");
                    break; // drop handle → old connection task exits → reconnect
                }
            }
        }
    });
}

async fn scan_once(cache: &Arc<MacLinkMapCache>, handle: &Handle) -> Result<(), std::io::Error> {
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

        match msg.header.state {
            NeighbourState::Failed | NeighbourState::Incomplete | NeighbourState::None => {
                continue;
            }
            _ => {}
        }

        let mut ipv6 = None;
        let mut mac_bytes = None;

        for attr in &msg.attributes {
            match attr {
                NeighbourAttribute::Destination(addr) => {
                    if let NeighbourAddress::Inet6(ip) = addr {
                        ipv6 = Some(*ip);
                    }
                }
                NeighbourAttribute::LinkLayerAddress(bytes) => {
                    if bytes.len() >= 6 && !bytes.iter().all(|&b| b == 0) {
                        mac_bytes = Some(bytes.as_slice());
                    }
                }
                _ => {}
            }
        }

        let ip = match ipv6 {
            Some(ip) if ip.is_unicast_link_local() => ip,
            _ => continue,
        };

        let mac = match mac_bytes.and_then(MacAddr::from_arry) {
            Some(mac) => mac,
            None => continue,
        };

        cache.record(msg.header.ifindex, mac, ip);
    }

    Ok(())
}
