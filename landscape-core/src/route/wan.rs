//! WAN route state: one active [`RouteTargetInfo`] per owner (interface or
//! container), default-router resolution, and change broadcasting.

use landscape_common::{
    ddns::IpFamily,
    sys_service::route_service::{RouteTargetInfo, dataplane::RouteTableDataplane},
};
use tokio::sync::broadcast;

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
    pub owner: String,
    pub family: IpFamily,
    pub kind: WanRouteEventKind,
}

fn reconcile_wan_route(
    routes: &mut WanRoutesByOwner,
    key: &str,
    info: RouteTargetInfo,
) -> WanRouteUpdate {
    match routes.get(key) {
        Some(old) if old == &info => WanRouteUpdate::Noop,
        _ => {
            let mut refresh_default_router = info.default_route;
            if let Some(old_info) = routes.insert(key.to_string(), info) {
                refresh_default_router = refresh_default_router || old_info.default_route;
            }
            WanRouteUpdate::Changed { refresh_default_router }
        }
    }
}

fn sync_default_ipv4_wan_route(
    dataplane: &dyn RouteTableDataplane,
    default_route: Option<RouteTargetInfo>,
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
    default_route: Option<RouteTargetInfo>,
) {
    if let Some(route) = default_route {
        let default_target = [(route, 1)];
        dataplane.replace_wan_slots_v6(0, &default_target);
    } else {
        dataplane.del_wan_slots_v6(0);
    }
    dataplane.invalidate_lan_cache();
}

impl IpRouteService {
    pub(crate) async fn clone_ipv4_wan_infos(&self) -> WanRoutesByOwner {
        clone_locked_state(&self.ipv4_wan_ifaces).await
    }

    pub(crate) async fn clone_ipv6_wan_infos(&self) -> WanRoutesByOwner {
        clone_locked_state(&self.ipv6_wan_ifaces).await
    }

    fn notify_wan_route_change(&self, owner: &str, family: IpFamily, kind: WanRouteEventKind) {
        let _ =
            self.wan_route_events.send(WanRouteEvent { owner: owner.to_string(), family, kind });
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

    async fn apply_removed_ipv4_wan_route(&self, removed: Option<RouteTargetInfo>) {
        if let Some(info) = removed
            && info.default_route
        {
            self.refresh_default_router().await;
        }
    }

    async fn apply_removed_ipv6_wan_route(&self, removed: Option<RouteTargetInfo>) {
        if let Some(info) = removed
            && info.default_route
        {
            self.refresh_default_router().await;
        }
    }

    pub async fn insert_ipv4_wan_route(&self, key: &str, info: RouteTargetInfo) {
        let update = {
            let mut lock = self.ipv4_wan_ifaces.write().await;
            reconcile_wan_route(&mut lock, key, info)
        };
        let changed = !matches!(update, WanRouteUpdate::Noop);

        self.apply_ipv4_wan_route_update(update).await;
        if changed {
            self.notify_wan_route_change(key, IpFamily::Ipv4, WanRouteEventKind::Upserted);
        }
    }

    pub async fn insert_ipv6_wan_route(&self, key: &str, info: RouteTargetInfo) {
        let update = {
            let mut lock = self.ipv6_wan_ifaces.write().await;
            reconcile_wan_route(&mut lock, key, info)
        };
        let changed = !matches!(update, WanRouteUpdate::Noop);

        self.apply_ipv6_wan_route_update(update).await;
        if changed {
            self.notify_wan_route_change(key, IpFamily::Ipv6, WanRouteEventKind::Upserted);
        }
    }

    pub async fn remove_ipv4_wan_route(&self, key: &str) {
        let removed = self.ipv4_wan_ifaces.write().await.remove(key);
        let had_removed = removed.is_some();
        self.apply_removed_ipv4_wan_route(removed).await;
        if had_removed {
            self.notify_wan_route_change(key, IpFamily::Ipv4, WanRouteEventKind::Removed);
        }
    }

    pub async fn remove_ipv6_wan_route(&self, key: &str) {
        let removed = self.ipv6_wan_ifaces.write().await.remove(key);
        let had_removed = removed.is_some();
        self.apply_removed_ipv6_wan_route(removed).await;
        if had_removed {
            self.notify_wan_route_change(key, IpFamily::Ipv6, WanRouteEventKind::Removed);
        }
    }

    pub async fn get_ipv4_wan_route(&self, key: &str) -> Option<RouteTargetInfo> {
        self.ipv4_wan_ifaces.read().await.get(key).cloned()
    }

    pub async fn get_ipv6_wan_route(&self, key: &str) -> Option<RouteTargetInfo> {
        self.ipv6_wan_ifaces.read().await.get(key).cloned()
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
        let ipv4_default =
            self.ipv4_wan_ifaces.read().await.values().find(|route| route.default_route).cloned();
        sync_default_ipv4_wan_route(&*self.dataplane, ipv4_default);

        let ipv6_default =
            self.ipv6_wan_ifaces.read().await.values().find(|route| route.default_route).cloned();
        sync_default_ipv6_wan_route(&*self.dataplane, ipv6_default);
    }

    /// Drop every docker-owned WAN route, refresh the default router, and
    /// notify subscribers about each removal.
    pub async fn remove_all_wan_docker(&self) {
        let mut removed_ipv4_owners = Vec::new();
        {
            let mut lock = self.ipv4_wan_ifaces.write().await;
            lock.retain(|key, value| {
                if value.is_docker {
                    removed_ipv4_owners.push(key.clone());
                }
                !value.is_docker
            });
        }

        let mut removed_ipv6_owners = Vec::new();
        {
            let mut lock = self.ipv6_wan_ifaces.write().await;
            lock.retain(|key, value| {
                if value.is_docker {
                    removed_ipv6_owners.push(key.clone());
                }
                !value.is_docker
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
