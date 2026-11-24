//! WAN route state: one active [`RouteTargetInfo`] per owner (link or
//! container), default-router resolution, and change broadcasting.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use landscape_common::{
    ddns::IpFamily,
    sys_service::route_service::{
        RouteOwner, RouteTargetInfo, WanRouteTarget, dataplane::RouteTableDataplane,
    },
};
use tokio::sync::broadcast;
use uuid::Uuid;

use super::{
    IpRouteService, WanRoutesByOwner, clone_locked_state,
    health::{LinkHealths, is_owner_available, is_owner_verified_healthy},
};

#[derive(Default)]
pub(crate) struct DefaultRouteIntents {
    ipv4_links: HashSet<Uuid>,
    ipv6_links: HashSet<Uuid>,
}

#[derive(Default)]
pub(crate) struct DefaultRouterSyncState {
    last_v4: Option<Option<WanRouteTarget>>,
    last_v6: Option<Option<WanRouteTarget>>,
}

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

fn is_failover_backup_link(owner: &RouteOwner, target: &WanRouteTarget) -> bool {
    !target.info.default_route && !target.info.is_docker && matches!(owner, RouteOwner::Link(_))
}

fn affects_default_router(owner: &RouteOwner, target: &WanRouteTarget) -> bool {
    target.info.default_route || is_failover_backup_link(owner, target)
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
            let mut refresh_default_router = affects_default_router(owner, &target);
            if let Some(old_target) = routes.insert(owner.clone(), target) {
                refresh_default_router =
                    refresh_default_router || affects_default_router(owner, &old_target);
            }
            WanRouteUpdate::Changed { refresh_default_router }
        }
    }
}

type OwnerSortKey<'a> = (u8, [u8; 16], &'a str);
type DefaultCandidateSortKey<'a> = (&'a str, u16, OwnerSortKey<'a>);
type BackupCandidateSortKey<'a> = (bool, DefaultCandidateSortKey<'a>);

fn owner_sort_key(owner: &RouteOwner) -> OwnerSortKey<'_> {
    match owner {
        RouteOwner::Link(id) => (0, *id.as_bytes(), ""),
        RouteOwner::Netns(name) => (1, [0; 16], name.as_str()),
    }
}

fn default_candidate_sort_key<'a>(
    owner: &'a RouteOwner,
    target: &'a WanRouteTarget,
) -> DefaultCandidateSortKey<'a> {
    (target.info.iface_name.as_str(), target.link_chain_id, owner_sort_key(owner))
}

fn backup_candidate_sort_key<'a>(
    healths: &LinkHealths,
    owner: &'a RouteOwner,
    target: &'a WanRouteTarget,
) -> BackupCandidateSortKey<'a> {
    // Verified-healthy backups take precedence over unmonitored `Unknown` backups,
    // while `Unknown` backups remain eligible whenever no verified-healthy backup exists.
    (!is_owner_verified_healthy(healths, owner), default_candidate_sort_key(owner, target))
}

/// Deterministically choose a single default WAN route for Flow 0 with health
/// failover:
/// 1. Prefer an available (`Healthy` or `Unknown`) primary (`default_route == true`).
/// 2. If all primaries are `Unhealthy` (or a configured primary route is absent
///    while redialing), fail over to an available non-docker WAN link backup.
/// 3. If every candidate is `Unhealthy`, fail open on the primary (or remaining
///    backup if the primary route is absent) rather than blackholing Flow 0.
pub(crate) fn select_default_wan_route(
    routes: &WanRoutesByOwner,
    healths: &LinkHealths,
    has_configured_default: bool,
) -> Option<WanRouteTarget> {
    let mut primaries: Vec<(&RouteOwner, &WanRouteTarget)> =
        routes.iter().filter(|(_, entry)| entry.info.default_route).collect();
    primaries.sort_by(|(owner_a, a), (owner_b, b)| {
        default_candidate_sort_key(owner_a, a).cmp(&default_candidate_sort_key(owner_b, b))
    });

    if let Some((_, target)) =
        primaries.iter().find(|(owner, _)| is_owner_available(healths, owner))
    {
        return Some((*target).clone());
    }

    if !primaries.is_empty() || has_configured_default {
        let mut backups: Vec<(&RouteOwner, &WanRouteTarget)> =
            routes.iter().filter(|(owner, entry)| is_failover_backup_link(owner, entry)).collect();
        backups.sort_by(|(owner_a, a), (owner_b, b)| {
            backup_candidate_sort_key(healths, owner_a, a)
                .cmp(&backup_candidate_sort_key(healths, owner_b, b))
        });

        if let Some((_, target)) =
            backups.iter().find(|(owner, _)| is_owner_available(healths, owner))
        {
            return Some((*target).clone());
        }

        if let Some((_, target)) = primaries.first() {
            return Some((*target).clone());
        }
        if has_configured_default && let Some((_, target)) = backups.first() {
            return Some((*target).clone());
        }
    }

    None
}

fn sync_default_ipv4_wan_route(
    dataplane: &dyn RouteTableDataplane,
    default_route: Option<&WanRouteTarget>,
) {
    if let Some(route) = default_route {
        let default_target = [(route.clone(), 1)];
        dataplane.replace_wan_slots_v4(0, &default_target);
    } else {
        dataplane.del_wan_slots_v4(0);
    }
}

fn sync_default_ipv6_wan_route(
    dataplane: &dyn RouteTableDataplane,
    default_route: Option<&WanRouteTarget>,
) {
    if let Some(route) = default_route {
        let default_target = [(route.clone(), 1)];
        dataplane.replace_wan_slots_v6(0, &default_target);
    } else {
        dataplane.del_wan_slots_v6(0);
    }
}

fn log_default_route_transition(
    family: &str,
    previous: Option<&WanRouteTarget>,
    next: Option<&WanRouteTarget>,
) {
    match (previous, next) {
        (Some(prev), Some(curr))
            if prev.info.iface_name != curr.info.iface_name
                || prev.info.default_route != curr.info.default_route =>
        {
            if !curr.info.default_route {
                tracing::warn!(
                    family,
                    from_iface = %prev.info.iface_name,
                    to_iface = %curr.info.iface_name,
                    "default WAN route failed over to backup link"
                );
            } else if !prev.info.default_route {
                tracing::info!(
                    family,
                    from_iface = %prev.info.iface_name,
                    to_iface = %curr.info.iface_name,
                    "default WAN route recovered to primary link"
                );
            } else {
                tracing::info!(
                    family,
                    from_iface = %prev.info.iface_name,
                    to_iface = %curr.info.iface_name,
                    "default WAN route switched"
                );
            }
        }
        (None, Some(curr)) if !curr.info.default_route => {
            tracing::warn!(
                family,
                to_iface = %curr.info.iface_name,
                "default WAN route activated on backup link while primary is unavailable"
            );
        }
        _ => {}
    }
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

fn normalize_kernel_nexthops<'a>(
    entries: impl IntoIterator<Item = &'a WanRouteTarget>,
    family: DefaultFamily,
) -> Vec<RouteTargetInfo> {
    let unspecified = match family {
        DefaultFamily::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        DefaultFamily::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };

    let mut candidates: Vec<RouteTargetInfo> = entries
        .into_iter()
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

/// Collect the kernel default-route nexthops for one family from the WAN
/// route state and current link health verdicts:
/// - Available (`Healthy` / `Unknown`) primary default targets with a usable
///   gateway (or dev-only point-to-point nexthop), deduplicated and sorted so
///   consecutive refreshes compare equal.
/// - When all primary targets are `Unhealthy` (or a configured primary route is
///   absent), fails over to the deterministic best available non-docker WAN
///   backup link.
/// - When all candidates are `Unhealthy`, fails open on the original primaries.
fn kernel_default_nexthops_for(
    routes: &WanRoutesByOwner,
    healths: &LinkHealths,
    has_configured_default: bool,
    family: DefaultFamily,
) -> Vec<RouteTargetInfo> {
    let primaries: Vec<(&RouteOwner, &WanRouteTarget)> = routes
        .iter()
        .filter(|(_, entry)| entry.info.default_route && usable_default_nexthop(entry, family))
        .collect();

    let available_primaries: Vec<&WanRouteTarget> = primaries
        .iter()
        .filter(|(owner, _)| is_owner_available(healths, owner))
        .map(|(_, entry)| *entry)
        .collect();
    if !available_primaries.is_empty() {
        return normalize_kernel_nexthops(available_primaries, family);
    }

    if !primaries.is_empty() || has_configured_default {
        let mut backups: Vec<(&RouteOwner, &WanRouteTarget)> = routes
            .iter()
            .filter(|(owner, entry)| {
                is_failover_backup_link(owner, entry) && usable_default_nexthop(entry, family)
            })
            .collect();
        backups.sort_by(|(owner_a, a), (owner_b, b)| {
            backup_candidate_sort_key(healths, owner_a, a)
                .cmp(&backup_candidate_sort_key(healths, owner_b, b))
        });

        if let Some((_, backup)) =
            backups.iter().find(|(owner, _)| is_owner_available(healths, owner))
        {
            return normalize_kernel_nexthops([*backup], family);
        }

        if !primaries.is_empty() {
            return normalize_kernel_nexthops(
                primaries.into_iter().map(|(_, entry)| entry),
                family,
            );
        }
        if has_configured_default && let Some((_, backup)) = backups.first() {
            return normalize_kernel_nexthops([*backup], family);
        }
    }

    Vec::new()
}

/// IPv4 nexthops for the kernel default route.
pub(crate) fn kernel_default_nexthops(
    routes: &WanRoutesByOwner,
    healths: &LinkHealths,
    has_configured_default: bool,
) -> Vec<RouteTargetInfo> {
    kernel_default_nexthops_for(routes, healths, has_configured_default, DefaultFamily::V4)
}

/// IPv6 nexthops for the kernel default route.
pub(crate) fn kernel_default_nexthops_v6(
    routes: &WanRoutesByOwner,
    healths: &LinkHealths,
    has_configured_default: bool,
) -> Vec<RouteTargetInfo> {
    kernel_default_nexthops_for(routes, healths, has_configured_default, DefaultFamily::V6)
}

/// Collect active non-docker IPv4 WAN links that need a dedicated `SkipRoute`
/// kernel policy route (`fwmark SkipRoute(chain_id)` -> dedicated per-chain
/// table). Sorted deterministically by `link_chain_id` and normalized to omit
/// fields that do not affect the kernel policy route (such as `default_route`,
/// `weight`, and `mac`), so Flow 0 failover flips never cause redundant kernel
/// churn.
pub(crate) fn kernel_wan_policy_targets(routes: &WanRoutesByOwner) -> Vec<WanRouteTarget> {
    let mut targets: Vec<WanRouteTarget> = routes
        .iter()
        .filter(|(owner, entry)| {
            matches!(owner, RouteOwner::Link(_))
                && !entry.info.is_docker
                && entry.link_chain_id != 0
                && entry.info.ifindex != 0
                && usable_default_nexthop(entry, DefaultFamily::V4)
        })
        .map(|(_, entry)| {
            let mut normalized = entry.clone();
            normalized.info.weight = 1;
            normalized.info.mac = None;
            normalized.info.default_route = false;
            normalized
        })
        .collect();

    targets.sort_by(|a, b| {
        a.link_chain_id
            .cmp(&b.link_chain_id)
            .then(a.info.ifindex.cmp(&b.info.ifindex))
            .then(a.info.iface_name.cmp(&b.info.iface_name))
    });
    targets.dedup_by_key(|target| target.link_chain_id);
    targets
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

    async fn default_route_intents(&self) -> (bool, bool) {
        let intents = self.default_route_intents.read().await;
        (!intents.ipv4_links.is_empty(), !intents.ipv6_links.is_empty())
    }

    /// Record whether an active WAN link is configured to provide a default
    /// route in IPv4 and/or IPv6. Used to allow Flow 0 failover to a healthy
    /// backup while the configured primary link's session is down or redialing.
    pub async fn set_link_default_intent(
        &self,
        link_id: Uuid,
        ipv4_default: bool,
        ipv6_default: bool,
    ) {
        let changed = {
            let mut intents = self.default_route_intents.write().await;
            let v4_changed = if ipv4_default {
                intents.ipv4_links.insert(link_id)
            } else {
                intents.ipv4_links.remove(&link_id)
            };
            let v6_changed = if ipv6_default {
                intents.ipv6_links.insert(link_id)
            } else {
                intents.ipv6_links.remove(&link_id)
            };
            v4_changed || v6_changed
        };
        if changed {
            self.refresh_default_router().await;
        }
    }

    /// Clear a stopped or deleted WAN link's default-route intent.
    pub async fn clear_link_default_intent(&self, link_id: Uuid) {
        self.set_link_default_intent(link_id, false, false).await;
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

    async fn apply_removed_ipv6_wan_route(
        &self,
        owner: &RouteOwner,
        removed: Option<WanRouteTarget>,
    ) {
        if let Some(entry) = removed
            && affects_default_router(owner, &entry)
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
        let refreshed = matches!(update, WanRouteUpdate::Changed { refresh_default_router: true });

        self.apply_ipv4_wan_route_update(update).await;
        if changed && !refreshed {
            self.kernel_default_notify.notify_one();
        }
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
        let route_affects_default =
            removed.as_ref().is_some_and(|entry| affects_default_router(owner, entry));

        // A link without its v4 WAN route has nothing to probe; clear its stale
        // health verdict before refreshing Flow 0 once for both changes.
        let health_event = match owner {
            RouteOwner::Link(link_id) => self.clear_link_health_inner(*link_id).await,
            RouteOwner::Netns(_) => None,
        };

        if route_affects_default || health_event.is_some() {
            self.refresh_default_router().await;
        } else if had_removed {
            self.kernel_default_notify.notify_one();
        }
        if let Some(event) = health_event {
            let _ = self.health_events.send(event);
        }
        if had_removed {
            self.notify_wan_route_change(owner, IpFamily::Ipv4, WanRouteEventKind::Removed);
        }
    }

    pub async fn remove_ipv6_wan_route(&self, owner: &RouteOwner) {
        let removed = self.ipv6_wan_ifaces.write().await.remove(owner);
        let had_removed = removed.is_some();
        self.apply_removed_ipv6_wan_route(owner, removed).await;
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
        let mut sync = self.default_router_sync.lock().await;
        let healths = self.clone_link_healths().await;
        let (has_v4_intent, has_v6_intent) = self.default_route_intents().await;

        let ipv4_default = {
            let routes = self.ipv4_wan_ifaces.read().await;
            select_default_wan_route(&routes, &healths, has_v4_intent)
        };
        let ipv6_default = {
            let routes = self.ipv6_wan_ifaces.read().await;
            select_default_wan_route(&routes, &healths, has_v6_intent)
        };

        let v4_changed = sync.last_v4.as_ref() != Some(&ipv4_default);
        let v6_changed = sync.last_v6.as_ref() != Some(&ipv6_default);

        if v4_changed {
            log_default_route_transition(
                "ipv4",
                sync.last_v4.as_ref().and_then(|v| v.as_ref()),
                ipv4_default.as_ref(),
            );
            sync_default_ipv4_wan_route(&*self.dataplane, ipv4_default.as_ref());
            sync.last_v4 = Some(ipv4_default);
        }

        if v6_changed {
            log_default_route_transition(
                "ipv6",
                sync.last_v6.as_ref().and_then(|v| v.as_ref()),
                ipv6_default.as_ref(),
            );
            sync_default_ipv6_wan_route(&*self.dataplane, ipv6_default.as_ref());
            sync.last_v6 = Some(ipv6_default);
        }

        if v4_changed || v6_changed {
            self.dataplane.invalidate_lan_cache();
        }
        drop(sync);

        // The kernel default routes are owned by the single-writer
        // reconcile loop: ring its doorbell instead of writing here. Always
        // notify because multi-primary kernel ECMP may change even when the
        // single eBPF Flow 0 target did not.
        self.kernel_default_notify.notify_one();
    }

    /// Reconcile the kernel IPv4 default route with the current WAN route
    /// state and link health verdicts. Snapshots the state right before
    /// writing, so a stale view can never be committed; a failed sync leaves
    /// the cache `None` so the next pass retries.
    pub(crate) async fn reconcile_kernel_default_ipv4(&self) {
        let healths = self.clone_link_healths().await;
        let (has_v4_intent, _) = self.default_route_intents().await;
        let defaults = {
            let routes = self.ipv4_wan_ifaces.read().await;
            kernel_default_nexthops(&routes, &healths, has_v4_intent)
        };
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
    /// state and link health verdicts. Same single-writer snapshot/retry
    /// contract as the IPv4 variant.
    pub(crate) async fn reconcile_kernel_default_ipv6(&self) {
        let healths = self.clone_link_healths().await;
        let (_, has_v6_intent) = self.default_route_intents().await;
        let defaults = {
            let routes = self.ipv6_wan_ifaces.read().await;
            kernel_default_nexthops_v6(&routes, &healths, has_v6_intent)
        };
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

    /// Reconcile per-WAN `SkipRoute` kernel IPv4 policy routes (`ip rule` +
    /// per-chain routing table) with the active IPv4 WAN links. An empty
    /// target set still invokes the dataplane so stale rules and tables from
    /// stopped links or prior crashes are cleaned up.
    pub(crate) async fn reconcile_kernel_wan_policy_ipv4(&self) {
        let targets = {
            let routes = self.ipv4_wan_ifaces.read().await;
            kernel_wan_policy_targets(&routes)
        };
        let mut cache = self.kernel_wan_policy_ipv4_cache.write().await;
        if *cache == Some(targets.clone()) {
            return;
        }
        if self.dataplane.sync_kernel_wan_policy_ipv4(&targets).await {
            *cache = Some(targets);
        } else {
            *cache = None;
        }
    }

    /// Spawn the kernel-default-route reconcile loop (IPv4 + IPv6): it
    /// wakes up right after every WAN route change (`notify_one` permit)
    /// and on a periodic safety-net tick. The ticker's first tick fires
    /// immediately, forcing a startup reconcile that pushes the current
    /// WAN default set and cleans up stale SkipRoute policy routes; when
    /// there is no default WAN, the `main` default route is left untouched.
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
                    service.reconcile_kernel_wan_policy_ipv4().await;
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
