//! LAN route state: per-owner IPv4 route buckets (same-subnet routes replace
//! each other) and per-key IPv6 routes, synced into the eBPF LAN route map.

use std::net::{IpAddr, Ipv4Addr};

use landscape_common::sys_service::route_service::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode};

use super::{IpRouteService, Ipv4LanRoutesByOwner, Ipv6LanRoutesByKey, clone_locked_state};

pub(super) enum Ipv4LanBucketUpdate {
    Noop,
    Changed { removed: Vec<LanRouteInfo>, added: LanRouteInfo },
}

pub(super) enum Ipv6LanRouteUpdate {
    Noop,
    Changed { removed: Option<LanRouteInfo>, added: LanRouteInfo },
}

// Keep the control-plane record unchanged. A WAN subnet produces an extra LPM
// entry for its interface address; an existing /32 already serves both purposes.
fn ipv4_dataplane_entries(route: LanRouteInfo) -> impl Iterator<Item = LanRouteInfo> {
    let host =
        (route.mode == LanRouteMode::WanReachable && route.prefix < 32 && route.iface_ip.is_ipv4())
            .then(|| LanRouteInfo { prefix: 32, ..route.clone() });
    std::iter::once(route).chain(host)
}

fn ipv4_host_addr(route: &LanRouteInfo) -> Option<Ipv4Addr> {
    match route.iface_ip {
        IpAddr::V4(ip) if route.prefix == 32 => Some(ip),
        _ => None,
    }
}

fn select_ipv4_host_route(routes: &Ipv4LanRoutesByOwner, ip: Ipv4Addr) -> Option<LanRouteInfo> {
    routes
        .values()
        .flatten()
        .filter(|r| {
            r.iface_ip == IpAddr::V4(ip) && (r.prefix == 32 || r.mode == LanRouteMode::WanReachable)
        })
        .min_by_key(|r| (r.mode != LanRouteMode::WanReachable, r.ifindex))
        .map(|r| LanRouteInfo { prefix: 32, ..r.clone() })
}

pub(super) fn reconcile_ipv4_lan_bucket(
    bucket: &mut Vec<LanRouteInfo>,
    new_info: LanRouteInfo,
) -> Ipv4LanBucketUpdate {
    if bucket.iter().any(|existing| existing == &new_info) {
        return Ipv4LanBucketUpdate::Noop;
    }

    let replace_wan = new_info.mode == LanRouteMode::WanReachable;
    let mut kept = Vec::with_capacity(bucket.len() + 1);
    let mut removed = Vec::new();

    for existing in std::mem::take(bucket) {
        if existing.is_same_subnet(&new_info)
            || (replace_wan && existing.mode == LanRouteMode::WanReachable)
        {
            removed.push(existing);
        } else {
            kept.push(existing);
        }
    }

    kept.push(new_info.clone());
    *bucket = kept;

    Ipv4LanBucketUpdate::Changed { removed, added: new_info }
}

fn select_ipv6_host_route<'a>(
    routes: &'a Ipv6LanRoutesByKey,
    entry: &LanRouteInfo,
) -> Option<&'a LanRouteInfo> {
    if entry.prefix != 128 {
        return None;
    }
    routes
        .values()
        .filter(|r| r.prefix == 128 && r.iface_ip == entry.iface_ip)
        .min_by_key(|r| (r.mode != LanRouteMode::WanReachable, r.ifindex))
}

impl IpRouteService {
    pub(super) fn upsert_ipv4_lan_routes_for_owner(
        &self,
        routes: &mut Ipv4LanRoutesByOwner,
        owner: &str,
        route: LanRouteInfo,
    ) -> Ipv4LanBucketUpdate {
        let bucket = routes.entry(owner.to_string()).or_default();
        let update = reconcile_ipv4_lan_bucket(bucket, route);
        if !matches!(update, Ipv4LanBucketUpdate::Noop) {
            self.refresh_reachable_local_ipv4_addrs(routes);
        }
        update
    }

    pub(super) fn remove_ipv4_lan_routes_for_owner(
        &self,
        routes: &mut Ipv4LanRoutesByOwner,
        owner: &str,
    ) -> Option<Vec<LanRouteInfo>> {
        let removed = routes.remove(owner);
        if removed.is_some() {
            self.refresh_reachable_local_ipv4_addrs(routes);
        }
        removed
    }

    pub(super) fn upsert_ipv6_lan_route_by_key(
        &self,
        routes: &mut Ipv6LanRoutesByKey,
        key: LanIPv6RouteKey,
        route: LanRouteInfo,
    ) -> Ipv6LanRouteUpdate {
        match routes.get(&key) {
            Some(old) if old == &route => Ipv6LanRouteUpdate::Noop,
            _ => {
                let removed = routes.insert(key, route.clone());
                self.refresh_reachable_local_ipv6_addrs(routes);
                Ipv6LanRouteUpdate::Changed { removed, added: route }
            }
        }
    }

    pub(super) fn remove_ipv6_lan_routes_for_iface(
        &self,
        routes: &mut Ipv6LanRoutesByKey,
        iface_name: &str,
    ) -> Vec<LanRouteInfo> {
        let remove_keys: Vec<_> =
            routes.keys().filter(|route_key| route_key.iface_name == iface_name).cloned().collect();

        let mut removed_routes = Vec::with_capacity(remove_keys.len());
        for route_key in remove_keys {
            if let Some(route) = routes.remove(&route_key) {
                removed_routes.push(route);
            }
        }

        if !removed_routes.is_empty() {
            self.refresh_reachable_local_ipv6_addrs(routes);
        }

        removed_routes
    }

    pub(super) fn remove_ipv6_lan_route_by_key_inner(
        &self,
        routes: &mut Ipv6LanRoutesByKey,
        key: &LanIPv6RouteKey,
    ) -> Option<LanRouteInfo> {
        let removed = routes.remove(key);
        if removed.is_some() {
            self.refresh_reachable_local_ipv6_addrs(routes);
        }
        removed
    }

    pub async fn insert_ipv4_lan_route(&self, key: &str, info: LanRouteInfo) {
        let mut routes = self.ipv4_lan_ifaces.write().await;
        let update = self.upsert_ipv4_lan_routes_for_owner(&mut routes, key, info);
        // Serialize publication with withdrawal: the LPM key has no interface component.
        self.sync_ipv4_lan_update(&routes, update);
    }

    pub async fn insert_ipv6_lan_route(&self, key: LanIPv6RouteKey, new_info: LanRouteInfo) {
        let mut routes = self.ipv6_lan_ifaces.write().await;
        let update = self.upsert_ipv6_lan_route_by_key(&mut routes, key, new_info);
        // Serialize publication with withdrawal: the LPM key has no interface component.
        if let Ipv6LanRouteUpdate::Changed { removed, added } = update {
            if let Some(old) = removed
                && !old.is_same_subnet(&added)
            {
                self.withdraw_ipv6_lan_route(&routes, old);
            }
            let wan = select_ipv6_host_route(&routes, &added)
                .filter(|r| r.mode == LanRouteMode::WanReachable);
            self.dataplane.add_lan_route(wan.cloned().unwrap_or(added));
        }
    }

    pub async fn remove_ipv4_lan_route(&self, key: &str) {
        let mut routes = self.ipv4_lan_ifaces.write().await;
        if let Some(removed_routes) = self.remove_ipv4_lan_routes_for_owner(&mut routes, key) {
            for entry in removed_routes.into_iter().flat_map(ipv4_dataplane_entries) {
                self.withdraw_ipv4_entry(&routes, entry);
            }
        }
    }

    pub async fn remove_ipv6_lan_route(&self, key: &str) {
        let mut routes = self.ipv6_lan_ifaces.write().await;
        for removed in self.remove_ipv6_lan_routes_for_iface(&mut routes, key) {
            self.withdraw_ipv6_lan_route(&routes, removed);
        }
    }

    pub async fn remove_ipv6_lan_route_by_key(&self, key: &LanIPv6RouteKey) {
        let mut routes = self.ipv6_lan_ifaces.write().await;
        if let Some(removed) = self.remove_ipv6_lan_route_by_key_inner(&mut routes, key) {
            self.withdraw_ipv6_lan_route(&routes, removed);
        }
    }

    fn sync_ipv4_lan_update(&self, routes: &Ipv4LanRoutesByOwner, update: Ipv4LanBucketUpdate) {
        let Ipv4LanBucketUpdate::Changed { removed, added } = update else { return };
        let added: Vec<_> = ipv4_dataplane_entries(added).collect();
        for old in removed.into_iter().flat_map(ipv4_dataplane_entries) {
            // Overwriting a shared LPM key doesn't require deleting it first.
            if !added.iter().any(|new| new.is_same_subnet(&old)) {
                self.withdraw_ipv4_entry(routes, old);
            }
        }
        for entry in added {
            let winner = ipv4_host_addr(&entry)
                .and_then(|ip| select_ipv4_host_route(routes, ip))
                .filter(|r| r.mode == LanRouteMode::WanReachable);
            self.dataplane.add_lan_route(winner.unwrap_or(entry));
        }
    }

    fn withdraw_ipv4_entry(&self, remaining: &Ipv4LanRoutesByOwner, entry: LanRouteInfo) {
        // The LPM key has no owner. Replace it in place if another owner still needs it.
        let survivor = if let Some(ip) = ipv4_host_addr(&entry) {
            select_ipv4_host_route(remaining, ip)
        } else {
            remaining
                .values()
                .flatten()
                .filter(|r| r.is_same_subnet(&entry))
                .min_by_key(|r| (r.mode == LanRouteMode::WanReachable, r.ifindex))
                .cloned()
        };
        if let Some(survivor) = survivor {
            self.dataplane.add_lan_route(survivor);
        } else {
            self.dataplane.del_lan_route(entry);
        }
    }

    fn withdraw_ipv6_lan_route(&self, remaining: &Ipv6LanRoutesByKey, removed: LanRouteInfo) {
        // PD links use the same host IID. With overlapping delegations two
        // interfaces can own the same /128, but rt6_lan_map has just one entry.
        if let Some(survivor) = select_ipv6_host_route(remaining, &removed) {
            self.dataplane.add_lan_route(survivor.clone());
        } else {
            self.dataplane.del_lan_route(removed);
        }
    }

    pub async fn get_all_ipv4_lan_routes(&self) -> Ipv4LanRoutesByOwner {
        clone_locked_state(&self.ipv4_lan_ifaces).await
    }

    pub async fn get_all_ipv6_lan_routes(&self) -> Ipv6LanRoutesByKey {
        clone_locked_state(&self.ipv6_lan_ifaces).await
    }

    pub async fn print_lan_ifaces(&self) {
        {
            let lock = self.ipv4_lan_ifaces.read().await;
            tracing::info!("ipv4 lan ifaces: {:?}", lock)
        }

        {
            let lock = self.ipv6_lan_ifaces.read().await;
            tracing::info!("ipv6 lan ifaces: {:?}", lock)
        }
    }
}
