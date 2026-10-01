//! LAN route state: per-owner IPv4 route buckets (same-subnet routes replace
//! each other) and per-key IPv6 routes, synced into the eBPF LAN route map.

use landscape_common::sys_service::route_service::{
    LanIPv6RouteKey, LanRouteInfo, dataplane::RouteTableDataplane,
};

use super::{IpRouteService, Ipv4LanRoutesByOwner, Ipv6LanRoutesByKey};

pub(super) enum Ipv4LanBucketUpdate {
    Noop,
    Changed { removed: Vec<LanRouteInfo>, added: LanRouteInfo },
}

pub(super) enum Ipv6LanRouteUpdate {
    Noop,
    Changed { removed: Option<LanRouteInfo>, added: LanRouteInfo },
}

pub(super) fn reconcile_ipv4_lan_bucket(
    bucket: &mut Vec<LanRouteInfo>,
    new_info: LanRouteInfo,
) -> Ipv4LanBucketUpdate {
    if bucket.iter().any(|existing| existing == &new_info) {
        return Ipv4LanBucketUpdate::Noop;
    }

    let mut kept = Vec::with_capacity(bucket.len() + 1);
    let mut removed = Vec::new();

    for existing in std::mem::take(bucket) {
        if existing.is_same_subnet(&new_info) {
            removed.push(existing);
        } else {
            kept.push(existing);
        }
    }

    kept.push(new_info.clone());
    *bucket = kept;

    Ipv4LanBucketUpdate::Changed { removed, added: new_info }
}

fn sync_ipv4_lan_update(dataplane: &dyn RouteTableDataplane, update: Ipv4LanBucketUpdate) {
    if let Ipv4LanBucketUpdate::Changed { removed, added } = update {
        sync_removed_lan_routes(dataplane, removed);
        dataplane.add_lan_route(added);
    }
}

fn sync_ipv6_lan_update(dataplane: &dyn RouteTableDataplane, update: Ipv6LanRouteUpdate) {
    if let Ipv6LanRouteUpdate::Changed { removed, added } = update {
        sync_removed_lan_routes(dataplane, removed);
        dataplane.add_lan_route(added);
    }
}

fn sync_removed_lan_routes(
    dataplane: &dyn RouteTableDataplane,
    routes: impl IntoIterator<Item = LanRouteInfo>,
) {
    for route in routes {
        dataplane.del_lan_route(route);
    }
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
        let update = {
            let mut lock = self.ipv4_lan_ifaces.write().await;
            self.upsert_ipv4_lan_routes_for_owner(&mut lock, key, info)
        };

        sync_ipv4_lan_update(&*self.dataplane, update);
    }

    pub async fn insert_ipv6_lan_route(&self, key: LanIPv6RouteKey, new_info: LanRouteInfo) {
        let update = {
            let mut lock = self.ipv6_lan_ifaces.write().await;
            self.upsert_ipv6_lan_route_by_key(&mut lock, key, new_info)
        };

        sync_ipv6_lan_update(&*self.dataplane, update);
    }

    pub async fn remove_ipv4_lan_route(&self, key: &str) {
        let removed = {
            let mut lock = self.ipv4_lan_ifaces.write().await;
            self.remove_ipv4_lan_routes_for_owner(&mut lock, key)
        };

        sync_removed_lan_routes(&*self.dataplane, removed.into_iter().flatten());
    }

    pub async fn remove_ipv6_lan_route(&self, key: &str) {
        let removed_routes = {
            let mut lock = self.ipv6_lan_ifaces.write().await;
            self.remove_ipv6_lan_routes_for_iface(&mut lock, key)
        };

        sync_removed_lan_routes(&*self.dataplane, removed_routes);
    }

    pub async fn remove_ipv6_lan_route_by_key(&self, key: &LanIPv6RouteKey) {
        let removed = {
            let mut lock = self.ipv6_lan_ifaces.write().await;
            self.remove_ipv6_lan_route_by_key_inner(&mut lock, key)
        };

        sync_removed_lan_routes(&*self.dataplane, removed);
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
