//! WAN route state: one active [`RouteTargetInfo`] per owner (link or
//! container), default-router resolution, and change broadcasting.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use landscape_common::{
    ddns::IpFamily,
    sys_service::route_service::{
        RouteOwner, RouteTargetInfo, WanRouteTarget, dataplane::RouteTableDataplane,
    },
};
use tokio::sync::broadcast;
use uuid::Uuid;

use super::{IpRouteService, WanRoutesByOwner, clone_locked_state};

enum WanRouteUpdate {
    Noop,
    Changed { refresh_default_router: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WanRouteEventKind {
    Upserted,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WanRouteEvent {
    pub owner: RouteOwner,
    pub family: IpFamily,
    pub kind: WanRouteEventKind,
}

fn reconcile_wan_route(
    routes: &mut WanRoutesByOwner,
    owner: &RouteOwner,
    target: WanRouteTarget,
) -> WanRouteUpdate {
    match routes.get(owner) {
        // The whole entry (info + link_chain_id) participates in the
        // comparison: a chain change must re-trigger the flow-target join
        // so the eBPF slot values pick up the new chain.
        Some(old) if old == &target => WanRouteUpdate::Noop,
        _ => {
            let mut refresh_default_router = target.info.default_route;
            if let Some(old_target) = routes.insert(owner.clone(), target) {
                refresh_default_router = refresh_default_router || old_target.info.default_route;
            }
            WanRouteUpdate::Changed { refresh_default_router }
        }
    }
}

fn sync_default_ipv4_wan_route(
    dataplane: &dyn RouteTableDataplane,
    default_route: Option<WanRouteTarget>,
) {
    if let Some(route) = default_route {
        let default_target = [(route, 1)];
        dataplane.replace_wan_slots_v4(0, &default_target);
    } else {
        dataplane.del_wan_slots_v4(0);
    }
    dataplane.invalidate_lan_cache();
}

fn sync_default_ipv6_wan_route(
    dataplane: &dyn RouteTableDataplane,
    default_route: Option<WanRouteTarget>,
) {
    if let Some(route) = default_route {
        let default_target = [(route, 1)];
        dataplane.replace_wan_slots_v6(0, &default_target);
    } else {
        dataplane.del_wan_slots_v6(0);
    }
    dataplane.invalidate_lan_cache();
}

/// Which address family's kernel default route a nexthop set feeds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DefaultFamily {
    V4,
    V6,
}

/// Whether a WAN route entry can contribute a nexthop to the requested
/// family's kernel default route.
fn usable_default_nexthop(entry: &WanRouteTarget, family: DefaultFamily) -> bool {
    if entry.info.dev_only_nexthop {
        return true;
    }
    match (family, entry.info.gateway_ip) {
        (DefaultFamily::V4, IpAddr::V4(gateway)) => gateway != Ipv4Addr::UNSPECIFIED,
        (DefaultFamily::V6, IpAddr::V6(gateway)) => gateway != Ipv6Addr::UNSPECIFIED,
        _ => false,
    }
}

/// Collect the kernel default-route nexthops for one family from the WAN
/// route state: default targets with a usable gateway (or a dev-only
/// point-to-point nexthop), deduplicated and sorted so consecutive
/// refreshes compare equal. Unspecified gateways and zero weights are
/// skipped/clamped, and fields that never reach the `ip` arguments are
/// normalized.
fn kernel_default_nexthops_for(
    routes: &WanRoutesByOwner,
    family: DefaultFamily,
) -> Vec<RouteTargetInfo> {
    let unspecified = match family {
        DefaultFamily::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        DefaultFamily::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let mut candidates: Vec<RouteTargetInfo> = routes
        .values()
        .filter(|entry| entry.info.default_route && usable_default_nexthop(entry, family))
        .map(|entry| {
            let mut nexthop = entry.info.clone();
            nexthop.weight = nexthop.weight.max(1);
            nexthop.ifindex = 0;
            nexthop.mac = None;
            nexthop.iface_ip = unspecified;
            nexthop
        })
        .collect();

    candidates.sort_by(|a, b| {
        a.iface_name
            .cmp(&b.iface_name)
            .then(a.gateway_ip.cmp(&b.gateway_ip))
            .then(a.weight.cmp(&b.weight))
    });
    candidates.dedup_by(|a, b| {
        a.iface_name == b.iface_name
            && a.gateway_ip == b.gateway_ip
            && a.weight == b.weight
            && a.dev_only_nexthop == b.dev_only_nexthop
    });

    candidates
}

/// IPv4 nexthops for the kernel default route.
pub(crate) fn kernel_default_nexthops(routes: &WanRoutesByOwner) -> Vec<RouteTargetInfo> {
    kernel_default_nexthops_for(routes, DefaultFamily::V4)
}

/// IPv6 nexthops for the kernel default route.
pub(crate) fn kernel_default_nexthops_v6(routes: &WanRoutesByOwner) -> Vec<RouteTargetInfo> {
    kernel_default_nexthops_for(routes, DefaultFamily::V6)
}

impl IpRouteService {
    pub(crate) async fn clone_ipv4_wan_infos(&self) -> WanRoutesByOwner {
        clone_locked_state(&self.ipv4_wan_ifaces).await
    }

    pub(crate) async fn clone_ipv6_wan_infos(&self) -> WanRoutesByOwner {
        clone_locked_state(&self.ipv6_wan_ifaces).await
    }

    fn notify_wan_route_change(
        &self,
        owner: &RouteOwner,
        family: IpFamily,
        kind: WanRouteEventKind,
    ) {
        let _ = self.wan_route_events.send(WanRouteEvent { owner: owner.clone(), family, kind });
    }

    async fn apply_ipv4_wan_route_update(&self, update: WanRouteUpdate) {
        if let WanRouteUpdate::Changed { refresh_default_router: true } = update {
            self.refresh_default_router().await;
        }
    }

    async fn apply_ipv6_wan_route_update(&self, update: WanRouteUpdate) {
        if let WanRouteUpdate::Changed { refresh_default_router: true } = update {
            self.refresh_default_router().await;
        }
    }

    async fn apply_removed_ipv4_wan_route(&self, removed: Option<WanRouteTarget>) {
        if let Some(entry) = removed
            && entry.info.default_route
        {
            self.refresh_default_router().await;
        }
    }

    async fn apply_removed_ipv6_wan_route(&self, removed: Option<WanRouteTarget>) {
        if let Some(entry) = removed
            && entry.info.default_route
        {
            self.refresh_default_router().await;
        }
    }

    pub async fn insert_ipv4_wan_route(&self, owner: &RouteOwner, target: WanRouteTarget) {
        let update = {
            let mut lock = self.ipv4_wan_ifaces.write().await;
            reconcile_wan_route(&mut lock, owner, target)
        };
        let changed = !matches!(update, WanRouteUpdate::Noop);

        self.apply_ipv4_wan_route_update(update).await;
        if changed {
            self.notify_wan_route_change(owner, IpFamily::Ipv4, WanRouteEventKind::Upserted);
        }
    }

    pub async fn insert_ipv6_wan_route(&self, owner: &RouteOwner, target: WanRouteTarget) {
        let update = {
            let mut lock = self.ipv6_wan_ifaces.write().await;
            reconcile_wan_route(&mut lock, owner, target)
        };
        let changed = !matches!(update, WanRouteUpdate::Noop);

        self.apply_ipv6_wan_route_update(update).await;
        if changed {
            self.notify_wan_route_change(owner, IpFamily::Ipv6, WanRouteEventKind::Upserted);
        }
    }

    pub async fn remove_ipv4_wan_route(&self, owner: &RouteOwner) {
        let removed = self.ipv4_wan_ifaces.write().await.remove(owner);
        let had_removed = removed.is_some();
        self.apply_removed_ipv4_wan_route(removed).await;
        // A link without its v4 WAN route has nothing to probe; its health
        // verdict is stale.
        if let RouteOwner::Link(link_id) = owner {
            self.clear_link_health(*link_id).await;
        }
        if had_removed {
            self.notify_wan_route_change(owner, IpFamily::Ipv4, WanRouteEventKind::Removed);
        }
    }

    pub async fn remove_ipv6_wan_route(&self, owner: &RouteOwner) {
        let removed = self.ipv6_wan_ifaces.write().await.remove(owner);
        let had_removed = removed.is_some();
        self.apply_removed_ipv6_wan_route(removed).await;
        if had_removed {
            self.notify_wan_route_change(owner, IpFamily::Ipv6, WanRouteEventKind::Removed);
        }
    }

    pub async fn insert_ipv4_link_route(&self, link_id: Uuid, target: WanRouteTarget) {
        self.insert_ipv4_wan_route(&RouteOwner::Link(link_id), target).await;
    }

    pub async fn insert_ipv6_link_route(&self, link_id: Uuid, target: WanRouteTarget) {
        self.insert_ipv6_wan_route(&RouteOwner::Link(link_id), target).await;
    }

    pub async fn remove_ipv4_link_route(&self, link_id: Uuid) {
        self.remove_ipv4_wan_route(&RouteOwner::Link(link_id)).await;
    }

    pub async fn remove_ipv6_link_route(&self, link_id: Uuid) {
        self.remove_ipv6_wan_route(&RouteOwner::Link(link_id)).await;
    }

    pub async fn get_ipv4_wan_route(&self, owner: &RouteOwner) -> Option<RouteTargetInfo> {
        self.ipv4_wan_ifaces.read().await.get(owner).map(|entry| entry.info.clone())
    }

    pub async fn get_ipv6_wan_route(&self, owner: &RouteOwner) -> Option<RouteTargetInfo> {
        self.ipv6_wan_ifaces.read().await.get(owner).map(|entry| entry.info.clone())
    }

    pub async fn get_all_ipv4_wan_routes(&self) -> WanRoutesByOwner {
        self.clone_ipv4_wan_infos().await
    }

    pub async fn get_all_ipv6_wan_routes(&self) -> WanRoutesByOwner {
        self.clone_ipv6_wan_infos().await
    }

    pub fn subscribe_wan_route_events(&self) -> broadcast::Receiver<WanRouteEvent> {
        self.wan_route_events.subscribe()
    }

    pub async fn refresh_default_router(&self) {
        let ipv4_default = self
            .ipv4_wan_ifaces
            .read()
            .await
            .values()
            .find(|entry| entry.info.default_route)
            .cloned();
        sync_default_ipv4_wan_route(&*self.dataplane, ipv4_default);

        let ipv6_default = self
            .ipv6_wan_ifaces
            .read()
            .await
            .values()
            .find(|entry| entry.info.default_route)
            .cloned();
        sync_default_ipv6_wan_route(&*self.dataplane, ipv6_default);

        // The kernel default routes are owned by the single-writer
        // reconcile loop: ring its doorbell instead of writing here.
        self.kernel_default_notify.notify_one();
    }

    /// Reconcile the kernel IPv4 default route with the current WAN route
    /// state. Snapshots the state right before writing, so a stale view
    /// can never be committed; a failed sync leaves the cache `None` so
    /// the next pass retries.
    pub(crate) async fn reconcile_kernel_default_ipv4(&self) {
        let defaults = kernel_default_nexthops(&*self.ipv4_wan_ifaces.read().await);
        let mut cache = self.kernel_default_ipv4_cache.write().await;
        if *cache == Some(defaults.clone()) {
            return;
        }
        if self.dataplane.sync_kernel_default_ipv4(&defaults).await {
            *cache = Some(defaults);
        } else {
            *cache = None;
        }
    }

    /// Reconcile the kernel IPv6 default route with the current WAN route
    /// state. Same single-writer snapshot/retry contract as the IPv4
    /// variant.
    pub(crate) async fn reconcile_kernel_default_ipv6(&self) {
        let defaults = kernel_default_nexthops_v6(&*self.ipv6_wan_ifaces.read().await);
        let mut cache = self.kernel_default_ipv6_cache.write().await;
        if *cache == Some(defaults.clone()) {
            return;
        }
        if self.dataplane.sync_kernel_default_ipv6(&defaults).await {
            *cache = Some(defaults);
        } else {
            *cache = None;
        }
    }

    /// Spawn the kernel-default-route reconcile loop (IPv4 + IPv6): it
    /// wakes up right after every WAN route change (`notify_one` permit)
    /// and on a periodic safety-net tick. The ticker's first tick fires
    /// immediately, forcing a startup reconcile that pushes the current
    /// WAN default set; when there is none, the kernel default route is
    /// left untouched.
    pub fn spawn_kernel_default_sync_loop(&self) {
        const KERNEL_DEFAULT_SYNC_INTERVAL_SECS: u64 = 30;
        let service = self.clone();
        landscape_common::concurrency::spawn_task(
            landscape_common::concurrency::task_label::task::ROUTE_KERNEL_DEFAULT_SYNC,
            async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    KERNEL_DEFAULT_SYNC_INTERVAL_SECS,
                ));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = service.kernel_default_notify.notified() => {}
                        _ = ticker.tick() => {}
                    }
                    service.reconcile_kernel_default_ipv4().await;
                    service.reconcile_kernel_default_ipv6().await;
                }
            },
        );
    }

    /// Drop every docker-owned WAN route, refresh the default router, and
    /// notify subscribers about each removal.
    pub async fn remove_all_wan_docker(&self) {
        let mut removed_ipv4_owners = Vec::new();
        {
            let mut lock = self.ipv4_wan_ifaces.write().await;
            lock.retain(|key, value| {
                if value.info.is_docker {
                    removed_ipv4_owners.push(key.clone());
                }
                !value.info.is_docker
            });
        }

        let mut removed_ipv6_owners = Vec::new();
        {
            let mut lock = self.ipv6_wan_ifaces.write().await;
            lock.retain(|key, value| {
                if value.info.is_docker {
                    removed_ipv6_owners.push(key.clone());
                }
                !value.info.is_docker
            });
        }

        if removed_ipv4_owners.is_empty() && removed_ipv6_owners.is_empty() {
            return;
        }

        self.refresh_default_router().await;
        for owner in removed_ipv4_owners {
            self.notify_wan_route_change(&owner, IpFamily::Ipv4, WanRouteEventKind::Removed);
        }
        for owner in removed_ipv6_owners {
            self.notify_wan_route_change(&owner, IpFamily::Ipv6, WanRouteEventKind::Removed);
        }
    }

    pub async fn print_wan_ifaces(&self) {
        {
            let lock = self.ipv4_wan_ifaces.read().await;
            tracing::info!("ipv4 wan ifaces: {:?}", lock)
        }

        {
            let lock = self.ipv6_wan_ifaces.read().await;
            tracing::info!("ipv6 wan ifaces: {:?}", lock)
        }
    }
}
