//! Reachable-local-address snapshots derived from LAN routes.
//!
//! [`LocalAddrView`] shares the snapshot handles with readers (e.g. the DNS
//! local-answer path) without exposing the service itself.

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use arc_swap::ArcSwap;
use landscape_common::{
    dns::dnr::{is_valid_dnr_ipv4_addr, is_valid_dnr_ipv6_addr},
    sys_service::route_service::{LanRouteInfo, LanRouteMode},
};

use super::{IpRouteService, Ipv4LanRoutesByOwner, Ipv6LanRoutesByKey, LocalAddrsByIfindex};

/// Lock-free shared view over the host's reachable local addresses.
///
/// Cloning the view shares the underlying swap handles, so readers always
/// observe the service's latest snapshot without holding any lock.
#[derive(Clone)]
pub struct LocalAddrView {
    ipv4_addrs: Arc<ArcSwap<Vec<IpAddr>>>,
    ipv6_addrs: Arc<ArcSwap<Vec<IpAddr>>>,
    ipv4_addrs_by_ifindex: Arc<ArcSwap<LocalAddrsByIfindex>>,
    ipv6_addrs_by_ifindex: Arc<ArcSwap<LocalAddrsByIfindex>>,
}

impl LocalAddrView {
    pub fn load_ipv4_addrs(&self) -> Arc<Vec<IpAddr>> {
        self.ipv4_addrs.load_full()
    }

    pub fn load_ipv6_addrs(&self) -> Arc<Vec<IpAddr>> {
        self.ipv6_addrs.load_full()
    }

    pub fn load_ipv4_addrs_for_ifindex(&self, ifindex: u32) -> Arc<Vec<IpAddr>> {
        load_addrs_for_ifindex(&self.ipv4_addrs_by_ifindex, ifindex)
    }

    pub fn load_ipv6_addrs_for_ifindex(&self, ifindex: u32) -> Arc<Vec<IpAddr>> {
        load_addrs_for_ifindex(&self.ipv6_addrs_by_ifindex, ifindex)
    }
}

fn load_addrs_for_ifindex(
    addrs_by_ifindex: &Arc<ArcSwap<LocalAddrsByIfindex>>,
    ifindex: u32,
) -> Arc<Vec<IpAddr>> {
    addrs_by_ifindex.load_full().get(&ifindex).cloned().unwrap_or_else(|| Arc::new(Vec::new()))
}

impl IpRouteService {
    /// Share the reachable-local-address snapshots (e.g. for the DNS local
    /// answer path).
    pub fn local_addr_view(&self) -> LocalAddrView {
        LocalAddrView {
            ipv4_addrs: self.reachable_local_ipv4_addrs.clone(),
            ipv6_addrs: self.reachable_local_ipv6_addrs.clone(),
            ipv4_addrs_by_ifindex: self.reachable_local_ipv4_addrs_by_ifindex.clone(),
            ipv6_addrs_by_ifindex: self.reachable_local_ipv6_addrs_by_ifindex.clone(),
        }
    }

    pub(super) fn refresh_reachable_local_ipv4_addrs(&self, routes: &Ipv4LanRoutesByOwner) {
        self.reachable_local_ipv4_addrs.store(Arc::new(collect_reachable_local_ipv4_addrs(
            routes.values().flat_map(|bucket| bucket.iter()),
        )));
        self.reachable_local_ipv4_addrs_by_ifindex.store(Arc::new(
            collect_reachable_local_ipv4_addrs_by_ifindex(
                routes.values().flat_map(|bucket| bucket.iter()),
            )
            .into_iter()
            .map(|(ifindex, addrs)| (ifindex, Arc::new(addrs)))
            .collect(),
        ));
    }

    pub(super) fn refresh_reachable_local_ipv6_addrs(&self, routes: &Ipv6LanRoutesByKey) {
        self.reachable_local_ipv6_addrs
            .store(Arc::new(collect_reachable_local_ipv6_addrs(routes.values())));
        self.reachable_local_ipv6_addrs_by_ifindex.store(Arc::new(
            collect_reachable_local_ipv6_addrs_by_ifindex(routes.values())
                .into_iter()
                .map(|(ifindex, addrs)| (ifindex, Arc::new(addrs)))
                .collect(),
        ));
    }
}

fn collect_reachable_local_ipv4_addrs<'a>(
    routes: impl Iterator<Item = &'a LanRouteInfo>,
) -> Vec<IpAddr> {
    let candidates: Vec<_> = routes
        .filter_map(|info| match (&info.mode, info.iface_ip) {
            (LanRouteMode::Reachable, IpAddr::V4(ip)) if is_valid_dns_answer_ipv4(ip) => {
                Some((info.iface_name.clone(), ip))
            }
            _ => None,
        })
        .collect();

    finalize_local_answer_addrs(candidates, IpAddr::V4)
}

fn collect_reachable_local_ipv4_addrs_by_ifindex<'a>(
    routes: impl Iterator<Item = &'a LanRouteInfo>,
) -> HashMap<u32, Vec<IpAddr>> {
    let mut candidates: Vec<_> = routes
        .filter_map(|info| match (&info.mode, info.iface_ip) {
            (LanRouteMode::Reachable, IpAddr::V4(ip)) if is_valid_dns_answer_ipv4(ip) => {
                Some((info.ifindex, info.iface_name.clone(), ip))
            }
            _ => None,
        })
        .collect();

    candidates
        .sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)).then_with(|| a.2.cmp(&b.2)));

    let mut seen = HashMap::<u32, HashSet<Ipv4Addr>>::new();
    let mut result = HashMap::<u32, Vec<IpAddr>>::new();

    for (ifindex, _, ip) in candidates {
        if seen.entry(ifindex).or_default().insert(ip) {
            result.entry(ifindex).or_default().push(IpAddr::V4(ip));
        }
    }

    result
}

fn collect_reachable_local_ipv6_addrs<'a>(
    routes: impl Iterator<Item = &'a LanRouteInfo>,
) -> Vec<IpAddr> {
    let candidates: Vec<_> = routes
        .filter_map(|info| match (&info.mode, info.iface_ip) {
            (LanRouteMode::Reachable, IpAddr::V6(ip)) if is_valid_dns_answer_ipv6(ip) => {
                Some((info.iface_name.clone(), ip))
            }
            _ => None,
        })
        .collect();

    finalize_local_answer_addrs(candidates, IpAddr::V6)
}

fn collect_reachable_local_ipv6_addrs_by_ifindex<'a>(
    routes: impl Iterator<Item = &'a LanRouteInfo>,
) -> HashMap<u32, Vec<IpAddr>> {
    let mut candidates: Vec<_> = routes
        .filter_map(|info| match (&info.mode, info.iface_ip) {
            (LanRouteMode::Reachable, IpAddr::V6(ip)) if is_valid_dns_answer_ipv6(ip) => {
                Some((info.ifindex, info.iface_name.clone(), ip))
            }
            _ => None,
        })
        .collect();

    candidates
        .sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)).then_with(|| a.2.cmp(&b.2)));

    let mut seen = HashMap::<u32, HashSet<Ipv6Addr>>::new();
    let mut result = HashMap::<u32, Vec<IpAddr>>::new();

    for (ifindex, _, ip) in candidates {
        if seen.entry(ifindex).or_default().insert(ip) {
            result.entry(ifindex).or_default().push(IpAddr::V6(ip));
        }
    }

    result
}

fn finalize_local_answer_addrs<T>(
    mut candidates: Vec<(String, T)>,
    to_ip_addr: impl Fn(T) -> IpAddr,
) -> Vec<IpAddr>
where
    T: Copy + Eq + Hash + Ord,
{
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(candidates.len());
    for (_, ip) in candidates {
        if seen.insert(ip) {
            result.push(to_ip_addr(ip));
        }
    }

    result
}

fn is_valid_dns_answer_ipv4(ip: Ipv4Addr) -> bool {
    is_valid_dnr_ipv4_addr(ip)
}

fn is_valid_dns_answer_ipv6(ip: Ipv6Addr) -> bool {
    is_valid_dnr_ipv6_addr(ip)
}
