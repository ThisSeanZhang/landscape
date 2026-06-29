use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use arc_swap::ArcSwap;
use hickory_proto::rr::RecordType;
use landscape_common::{
    config::FlowId,
    ddns::IpFamily,
    dns::dnr::{is_valid_dnr_ipv4_addr, is_valid_dnr_ipv6_addr},
    event::route::RouteEvent,
    flow::{config::FlowConfig, FlowTarget},
    route::{LanIPv6RouteKey, LanRouteInfo, LanRouteMode, RouteTargetInfo},
};
use landscape_database::flow_rule::repository::FlowConfigRepository;
use landscape_dns::server::LocalDnsAnswerProvider;
use landscape_ebpf::map_setting::route::{add_lan_route, del_lan_route};
use tokio::sync::{broadcast, mpsc, RwLock};

use landscape_common::database::LandscapeStore;

type ShareRwLock<T> = Arc<RwLock<T>>;
// One owner (interface / container) maps to one active WAN route target.
type WanRoutesByOwner = HashMap<String, RouteTargetInfo>;
// One owner may publish multiple IPv4 LAN routes; same-subnet routes replace each other.
type Ipv4LanRoutesByOwner = HashMap<String, Vec<LanRouteInfo>>;
// Each IPv6 LAN route is keyed individually to support precise updates and removals.
type Ipv6LanRoutesByKey = HashMap<LanIPv6RouteKey, LanRouteInfo>;

#[derive(Clone)]
pub struct IpRouteService {
    flow_repo: FlowConfigRepository,
    ipv4_wan_ifaces: ShareRwLock<WanRoutesByOwner>,
    ipv6_wan_ifaces: ShareRwLock<WanRoutesByOwner>,
    wan_route_events: broadcast::Sender<WanRouteEvent>,

    ipv4_lan_ifaces: ShareRwLock<Ipv4LanRoutesByOwner>,
    ipv6_lan_ifaces: ShareRwLock<Ipv6LanRoutesByKey>,
    reachable_local_ipv4_addrs: Arc<ArcSwap<Vec<IpAddr>>>,
    reachable_local_ipv4_addrs_by_ifindex: Arc<ArcSwap<HashMap<u32, Arc<Vec<IpAddr>>>>>,
    reachable_local_ipv6_addrs: Arc<ArcSwap<Vec<IpAddr>>>,
    reachable_local_ipv6_addrs_by_ifindex: Arc<ArcSwap<HashMap<u32, Arc<Vec<IpAddr>>>>>,
}

enum Ipv4LanBucketUpdate {
    Noop,
    Changed { removed: Vec<LanRouteInfo>, added: LanRouteInfo },
}

enum Ipv6LanRouteUpdate {
    Noop,
    Changed { removed: Option<LanRouteInfo>, added: LanRouteInfo },
}

enum WanRouteUpdate {
    Noop,
    Changed { refresh_default_router: bool, target: FlowTarget },
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

fn reconcile_ipv4_lan_bucket(
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

fn reconcile_wan_route(
    routes: &mut WanRoutesByOwner,
    key: &str,
    info: RouteTargetInfo,
) -> WanRouteUpdate {
    match routes.get(key) {
        Some(old) if old == &info => WanRouteUpdate::Noop,
        _ => {
            let mut refresh_default_router = info.default_route;
            if let Some(old_info) = routes.insert(key.to_string(), info.clone()) {
                refresh_default_router = refresh_default_router || old_info.default_route;
            }
            WanRouteUpdate::Changed {
                refresh_default_router,
                target: info.get_flow_target(),
            }
        }
    }
}

fn sync_ipv4_lan_update(update: Ipv4LanBucketUpdate) {
    if let Ipv4LanBucketUpdate::Changed { removed, added } = update {
        sync_removed_lan_routes(removed);
        add_lan_route(added);
    }
}

fn sync_ipv6_lan_update(update: Ipv6LanRouteUpdate) {
    if let Ipv6LanRouteUpdate::Changed { removed, added } = update {
        sync_removed_lan_routes(removed);
        add_lan_route(added);
    }
}

fn sync_removed_lan_routes(routes: impl IntoIterator<Item = LanRouteInfo>) {
    for route in routes {
        del_lan_route(route);
    }
}

fn sync_default_ipv4_wan_route(default_route: Option<RouteTargetInfo>) {
    if let Some(route) = default_route {
        let default_target = [(route, 1)];
        landscape_ebpf::map_setting::route::replace_wan_route_slots_v4(0, &default_target);
    } else {
        landscape_ebpf::map_setting::route::del_wan_route_slots_v4(0);
    }
    landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
}

fn sync_default_ipv6_wan_route(default_route: Option<RouteTargetInfo>) {
    if let Some(route) = default_route {
        let default_target = [(route, 1)];
        landscape_ebpf::map_setting::route::replace_wan_route_slots_v6(0, &default_target);
    } else {
        landscape_ebpf::map_setting::route::del_wan_route_slots_v6(0);
    }
    landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
}

fn find_route_target<'a>(
    wan_infos: &'a WanRoutesByOwner,
    target: &FlowTarget,
) -> Option<&'a RouteTargetInfo> {
    match target {
        FlowTarget::Interface { name } => wan_infos.get(name),
        FlowTarget::Netns { container_name } => wan_infos.get(container_name),
    }
}

fn collect_target_refresh_result(
    flow_configs: &Vec<FlowConfig>,
    wan_infos: &WanRoutesByOwner,
) -> HashMap<FlowId, Vec<(RouteTargetInfo, u32)>> {
    let mut result = HashMap::new();

    for flow_config in flow_configs {
        let targets = if flow_config.enable {
            flow_config
                .flow_targets
                .iter()
                .filter_map(|target| {
                    find_route_target(wan_infos, &target.target)
                        .cloned()
                        .map(|route| (route, target.weight))
                })
                .collect()
        } else {
            Vec::new()
        };

        result.insert(flow_config.flow_id, targets);
    }

    result
}

fn apply_ipv4_target_refresh_result(result: HashMap<FlowId, Vec<(RouteTargetInfo, u32)>>) {
    tracing::info!("ipv4 flow target refresh result: {result:#?}");

    for (flow_id, configs) in result {
        if configs.is_empty() {
            landscape_ebpf::map_setting::route::del_wan_route_slots_v4(flow_id);
        } else {
            landscape_ebpf::map_setting::route::replace_wan_route_slots_v4(flow_id, &configs);
        }
    }
}

fn apply_ipv6_target_refresh_result(result: HashMap<FlowId, Vec<(RouteTargetInfo, u32)>>) {
    tracing::info!("ipv6 flow target refresh result: {result:#?}");

    for (flow_id, configs) in result {
        if configs.is_empty() {
            landscape_ebpf::map_setting::route::del_wan_route_slots_v6(flow_id);
        } else {
            landscape_ebpf::map_setting::route::replace_wan_route_slots_v6(flow_id, &configs);
        }
    }
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

async fn clone_locked_state<T: Clone>(state: &ShareRwLock<T>) -> T {
    state.read().await.clone()
}

impl IpRouteService {
    pub fn new(
        route_event_sender: mpsc::Receiver<RouteEvent>,
        flow_repo: FlowConfigRepository,
    ) -> Self {
        let (wan_route_events, _) = broadcast::channel(64);
        let service = IpRouteService {
            flow_repo,
            ipv4_wan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv6_wan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            wan_route_events,
            ipv4_lan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            ipv6_lan_ifaces: Arc::new(RwLock::new(HashMap::new())),
            reachable_local_ipv4_addrs: Arc::new(ArcSwap::from_pointee(Vec::new())),
            reachable_local_ipv4_addrs_by_ifindex: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            reachable_local_ipv6_addrs: Arc::new(ArcSwap::from_pointee(Vec::new())),
            reachable_local_ipv6_addrs_by_ifindex: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        };
        service.spawn_route_event_worker(route_event_sender);
        service
    }

    fn spawn_route_event_worker(&self, mut route_event_receiver: mpsc::Receiver<RouteEvent>) {
        let route_service = self.clone();
        tokio::spawn(async move {
            while let Some(event) = route_event_receiver.recv().await {
                route_service.handle_route_event(event).await;
            }
        });
    }

    async fn handle_route_event(&self, event: RouteEvent) {
        let Some(flow_configs) = self.load_flow_configs_for_event(event).await else {
            return;
        };

        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;

        refresh_ipv4_target_bpf_map(&flow_configs, ipv4_wan_infos);
        refresh_ipv6_target_bpf_map(&flow_configs, ipv6_wan_infos);
        landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }

    async fn load_flow_configs_for_event(&self, event: RouteEvent) -> Option<Vec<FlowConfig>> {
        match event {
            RouteEvent::FlowRuleUpdate { flow_id: Some(flow_id) } => self
                .flow_repo
                .find_by_flow_id(flow_id)
                .await
                .ok()
                .flatten()
                .map(|flow_config| vec![flow_config]),
            RouteEvent::FlowRuleUpdate { flow_id: None } => {
                Some(self.flow_repo.list().await.unwrap_or_default())
            }
        }
    }

    async fn clone_ipv4_wan_infos(&self) -> WanRoutesByOwner {
        clone_locked_state(&self.ipv4_wan_ifaces).await
    }

    async fn clone_ipv6_wan_infos(&self) -> WanRoutesByOwner {
        clone_locked_state(&self.ipv6_wan_ifaces).await
    }

    fn notify_wan_route_change(&self, owner: &str, family: IpFamily, kind: WanRouteEventKind) {
        let _ =
            self.wan_route_events.send(WanRouteEvent { owner: owner.to_string(), family, kind });
    }

    async fn apply_ipv4_wan_route_update(&self, update: WanRouteUpdate) {
        if let WanRouteUpdate::Changed { refresh_default_router, target } = update {
            self.refresh_ipv4_target_map(target).await;
            if refresh_default_router {
                self.refresh_default_router().await;
            }
        }
    }

    async fn apply_ipv6_wan_route_update(&self, update: WanRouteUpdate) {
        if let WanRouteUpdate::Changed { refresh_default_router, target } = update {
            self.refresh_ipv6_target_map(target).await;
            if refresh_default_router {
                self.refresh_default_router().await;
            }
        }
    }

    async fn apply_removed_ipv4_wan_route(&self, removed: Option<RouteTargetInfo>) {
        if let Some(info) = removed {
            self.refresh_ipv4_target_map(info.get_flow_target()).await;
            if info.default_route {
                self.refresh_default_router().await;
            }
        }
    }

    async fn apply_removed_ipv6_wan_route(&self, removed: Option<RouteTargetInfo>) {
        if let Some(info) = removed {
            self.refresh_ipv6_target_map(info.get_flow_target()).await;
            if info.default_route {
                self.refresh_default_router().await;
            }
        }
    }

    fn upsert_ipv4_lan_routes_for_owner(
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

    fn remove_ipv4_lan_routes_for_owner(
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

    fn upsert_ipv6_lan_route_by_key(
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

    fn remove_ipv6_lan_routes_for_iface(
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

    fn remove_ipv6_lan_route_by_key_inner(
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

    pub async fn remove_all_wan_docker(&self) {
        {
            let mut lock = self.ipv4_wan_ifaces.write().await;
            lock.retain(|_, value| !value.is_docker);
        }

        {
            let mut lock = self.ipv6_wan_ifaces.write().await;
            lock.retain(|_, value| !value.is_docker);
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

    pub async fn insert_ipv6_lan_route(&self, key: LanIPv6RouteKey, new_info: LanRouteInfo) {
        let update = {
            let mut lock = self.ipv6_lan_ifaces.write().await;
            self.upsert_ipv6_lan_route_by_key(&mut lock, key, new_info)
        };

        sync_ipv6_lan_update(update);
    }

    pub async fn insert_ipv4_lan_route(&self, key: &str, info: LanRouteInfo) {
        let update = {
            let mut lock = self.ipv4_lan_ifaces.write().await;
            self.upsert_ipv4_lan_routes_for_owner(&mut lock, key, info)
        };

        sync_ipv4_lan_update(update);
    }

    pub async fn remove_ipv6_lan_route(&self, key: &str) {
        let removed_routes = {
            let mut lock = self.ipv6_lan_ifaces.write().await;
            self.remove_ipv6_lan_routes_for_iface(&mut lock, key)
        };

        sync_removed_lan_routes(removed_routes);
    }

    pub async fn remove_ipv6_lan_route_by_key(&self, key: &LanIPv6RouteKey) {
        let removed = {
            let mut lock = self.ipv6_lan_ifaces.write().await;
            self.remove_ipv6_lan_route_by_key_inner(&mut lock, key)
        };

        sync_removed_lan_routes(removed);
    }

    pub async fn remove_ipv4_lan_route(&self, key: &str) {
        let removed = {
            let mut lock = self.ipv4_lan_ifaces.write().await;
            self.remove_ipv4_lan_routes_for_owner(&mut lock, key)
        };

        sync_removed_lan_routes(removed.into_iter().flatten());
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

    pub async fn remove_ipv4_wan_route(&self, key: &str) {
        let removed = self.ipv4_wan_ifaces.write().await.remove(key);
        let had_removed = removed.is_some();
        self.apply_removed_ipv4_wan_route(removed).await;
        if had_removed {
            self.notify_wan_route_change(key, IpFamily::Ipv4, WanRouteEventKind::Removed);
        }
    }

    pub async fn get_ipv4_wan_route(&self, key: &str) -> Option<RouteTargetInfo> {
        self.ipv4_wan_ifaces.read().await.get(key).cloned()
    }

    pub async fn get_all_ipv4_wan_routes(&self) -> HashMap<String, RouteTargetInfo> {
        self.clone_ipv4_wan_infos().await
    }

    pub async fn remove_ipv6_wan_route(&self, key: &str) {
        let removed = self.ipv6_wan_ifaces.write().await.remove(key);
        let had_removed = removed.is_some();
        self.apply_removed_ipv6_wan_route(removed).await;
        if had_removed {
            self.notify_wan_route_change(key, IpFamily::Ipv6, WanRouteEventKind::Removed);
        }
    }

    pub async fn get_ipv6_wan_route(&self, key: &str) -> Option<RouteTargetInfo> {
        self.ipv6_wan_ifaces.read().await.get(key).cloned()
    }

    pub async fn get_all_ipv6_wan_routes(&self) -> HashMap<String, RouteTargetInfo> {
        self.clone_ipv6_wan_infos().await
    }

    pub fn subscribe_wan_route_events(&self) -> broadcast::Receiver<WanRouteEvent> {
        self.wan_route_events.subscribe()
    }

    pub async fn refresh_default_router(&self) {
        let ipv4_default =
            self.ipv4_wan_ifaces.read().await.values().find(|route| route.default_route).cloned();
        sync_default_ipv4_wan_route(ipv4_default);

        let ipv6_default =
            self.ipv6_wan_ifaces.read().await.values().find(|route| route.default_route).cloned();
        sync_default_ipv6_wan_route(ipv6_default);
    }

    pub async fn refresh_ipv4_target_map(&self, t: FlowTarget) {
        let flow_configs = self.flow_repo.find_by_target(t).await.unwrap_or_default();
        let ipv4_wan_infos = self.clone_ipv4_wan_infos().await;
        refresh_ipv4_target_bpf_map(&flow_configs, ipv4_wan_infos);
        landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }

    pub async fn refresh_ipv6_target_map(&self, t: FlowTarget) {
        let flow_configs = self.flow_repo.find_by_target(t).await.unwrap_or_default();
        let ipv6_wan_infos = self.clone_ipv6_wan_infos().await;
        refresh_ipv6_target_bpf_map(&flow_configs, ipv6_wan_infos);
        landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    }

    pub fn load_reachable_local_ipv4_addrs(&self) -> Arc<Vec<IpAddr>> {
        self.reachable_local_ipv4_addrs.load_full()
    }

    pub fn load_reachable_local_ipv6_addrs(&self) -> Arc<Vec<IpAddr>> {
        self.reachable_local_ipv6_addrs.load_full()
    }

    fn load_reachable_local_ipv4_addrs_for_ifindex(&self, ifindex: u32) -> Arc<Vec<IpAddr>> {
        self.reachable_local_ipv4_addrs_by_ifindex
            .load_full()
            .get(&ifindex)
            .cloned()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    fn load_reachable_local_ipv6_addrs_for_ifindex(&self, ifindex: u32) -> Arc<Vec<IpAddr>> {
        self.reachable_local_ipv6_addrs_by_ifindex
            .load_full()
            .get(&ifindex)
            .cloned()
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    fn refresh_reachable_local_ipv4_addrs(&self, routes: &Ipv4LanRoutesByOwner) {
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

    fn refresh_reachable_local_ipv6_addrs(&self, routes: &Ipv6LanRoutesByKey) {
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

impl LocalDnsAnswerProvider for IpRouteService {
    fn load_local_answer_addrs(&self, query_type: RecordType) -> Arc<Vec<IpAddr>> {
        match query_type {
            RecordType::A => self.load_reachable_local_ipv4_addrs(),
            RecordType::AAAA => self.load_reachable_local_ipv6_addrs(),
            _ => Arc::new(Vec::new()),
        }
    }

    fn load_local_answer_addrs_for_ifindex(
        &self,
        query_type: RecordType,
        ifindex: u32,
    ) -> Arc<Vec<IpAddr>> {
        if ifindex == 0 {
            return self.load_local_answer_addrs(query_type);
        }

        match query_type {
            RecordType::A => self.load_reachable_local_ipv4_addrs_for_ifindex(ifindex),
            RecordType::AAAA => self.load_reachable_local_ipv6_addrs_for_ifindex(ifindex),
            _ => Arc::new(Vec::new()),
        }
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

fn is_valid_dns_answer_ipv4(ip: Ipv4Addr) -> bool {
    is_valid_dnr_ipv4_addr(ip)
}

fn is_valid_dns_answer_ipv6(ip: Ipv6Addr) -> bool {
    is_valid_dnr_ipv6_addr(ip)
}

pub fn refresh_ipv4_target_bpf_map(
    flow_configs: &Vec<FlowConfig>,
    ipv4_wan_infos: HashMap<String, RouteTargetInfo>,
) {
    let result = collect_target_refresh_result(flow_configs, &ipv4_wan_infos);
    apply_ipv4_target_refresh_result(result);
}

pub fn refresh_ipv6_target_bpf_map(
    flow_configs: &Vec<FlowConfig>,
    ipv6_wan_infos: HashMap<String, RouteTargetInfo>,
) {
    let result = collect_target_refresh_result(flow_configs, &ipv6_wan_infos);
    apply_ipv6_target_refresh_result(result);
}

pub async fn test_used_ip_route() -> (mpsc::Sender<RouteEvent>, IpRouteService) {
    let db_store_provider =
        landscape_database::provider::LandscapeDBServiceProvider::mem_test_db().await;
    let flow_repo = db_store_provider.flow_rule_store();
    let (route_tx, route_rx) = mpsc::channel(1);
    let ip_route = IpRouteService::new(route_rx, flow_repo);
    (route_tx, ip_route)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use landscape_common::flow::WeightedFlowTarget;
    use uuid::Uuid;

    use super::*;

    fn ipv4_wan_route(iface_name: &str, iface_ip: Ipv4Addr) -> RouteTargetInfo {
        RouteTargetInfo {
            weight: 1,
            ifindex: 1,
            mac: None,
            default_route: true,
            is_docker: false,
            iface_name: iface_name.to_string(),
            iface_ip: IpAddr::V4(iface_ip),
            gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    fn ipv4_lan_route(
        ifindex: u32,
        iface_name: &str,
        iface_ip: Ipv4Addr,
        prefix: u8,
        mode: LanRouteMode,
    ) -> LanRouteInfo {
        LanRouteInfo {
            ifindex,
            iface_name: iface_name.to_string(),
            iface_ip: IpAddr::V4(iface_ip),
            mac: None,
            prefix,
            mode,
        }
    }

    fn ipv6_lan_route(
        ifindex: u32,
        iface_name: &str,
        iface_ip: Ipv6Addr,
        prefix: u8,
        mode: LanRouteMode,
    ) -> LanRouteInfo {
        LanRouteInfo {
            ifindex,
            iface_name: iface_name.to_string(),
            iface_ip: IpAddr::V6(iface_ip),
            mac: None,
            prefix,
            mode,
        }
    }

    fn run_async_test(test: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test);
    }

    #[test]
    fn wan_route_events_only_fire_on_real_changes() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let mut events = service.subscribe_wan_route_events();
            let route = ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 10));

            service.insert_ipv4_wan_route("wan0", route.clone()).await;
            assert_eq!(
                events.recv().await.unwrap(),
                WanRouteEvent {
                    owner: "wan0".to_string(),
                    family: IpFamily::Ipv4,
                    kind: WanRouteEventKind::Upserted,
                }
            );

            service.insert_ipv4_wan_route("wan0", route).await;
            assert!(tokio::time::timeout(Duration::from_millis(50), events.recv()).await.is_err());

            service.remove_ipv4_wan_route("wan0").await;
            assert_eq!(
                events.recv().await.unwrap(),
                WanRouteEvent {
                    owner: "wan0".to_string(),
                    family: IpFamily::Ipv4,
                    kind: WanRouteEventKind::Removed,
                }
            );
        });
    }

    #[test]
    fn reachable_local_ipv4_addrs_filter_invalid_entries_and_next_hop() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let mut routes = service.ipv4_lan_ifaces.write().await;
            routes.insert(
                "wan0".to_string(),
                vec![ipv4_lan_route(
                    1,
                    "wan0",
                    Ipv4Addr::new(192, 168, 2, 1),
                    24,
                    LanRouteMode::Reachable,
                )],
            );
            routes.insert(
                "lan0".to_string(),
                vec![ipv4_lan_route(
                    2,
                    "lan0",
                    Ipv4Addr::new(192, 168, 1, 1),
                    24,
                    LanRouteMode::Reachable,
                )],
            );
            routes.insert(
                "lan0-nexthop".to_string(),
                vec![ipv4_lan_route(
                    2,
                    "lan0",
                    Ipv4Addr::new(192, 168, 1, 254),
                    24,
                    LanRouteMode::NextHop {
                        next_hop_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
                    },
                )],
            );
            routes.insert(
                "loopback".to_string(),
                vec![ipv4_lan_route(3, "lo", Ipv4Addr::LOCALHOST, 8, LanRouteMode::Reachable)],
            );
            routes.insert(
                "lan1".to_string(),
                vec![ipv4_lan_route(
                    4,
                    "lan1",
                    Ipv4Addr::new(192, 168, 1, 1),
                    24,
                    LanRouteMode::Reachable,
                )],
            );
            service.refresh_reachable_local_ipv4_addrs(&routes);
            drop(routes);

            assert_eq!(
                service.load_reachable_local_ipv4_addrs().as_ref(),
                &vec![
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))
                ]
            );
        });
    }

    #[test]
    fn reachable_local_ipv6_addrs_keep_link_local_and_deduplicate() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let mut routes = service.ipv6_lan_ifaces.write().await;
            routes.insert(
                LanIPv6RouteKey { iface_name: "lan0".to_string(), subnet_index: 0 },
                LanRouteInfo {
                    ifindex: 1,
                    iface_name: "lan0".to_string(),
                    iface_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    mac: None,
                    prefix: 64,
                    mode: LanRouteMode::Reachable,
                },
            );
            routes.insert(
                LanIPv6RouteKey { iface_name: "lan1".to_string(), subnet_index: 0 },
                LanRouteInfo {
                    ifindex: 2,
                    iface_name: "lan1".to_string(),
                    iface_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    mac: None,
                    prefix: 64,
                    mode: LanRouteMode::Reachable,
                },
            );
            routes.insert(
                LanIPv6RouteKey { iface_name: "lan2".to_string(), subnet_index: 0 },
                LanRouteInfo {
                    ifindex: 3,
                    iface_name: "lan2".to_string(),
                    iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    mac: None,
                    prefix: 64,
                    mode: LanRouteMode::Reachable,
                },
            );
            routes.insert(
                LanIPv6RouteKey { iface_name: "lan3".to_string(), subnet_index: 0 },
                LanRouteInfo {
                    ifindex: 4,
                    iface_name: "lan3".to_string(),
                    iface_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    mac: None,
                    prefix: 128,
                    mode: LanRouteMode::Reachable,
                },
            );
            routes.insert(
                LanIPv6RouteKey { iface_name: "lan4".to_string(), subnet_index: 0 },
                LanRouteInfo {
                    ifindex: 5,
                    iface_name: "lan4".to_string(),
                    iface_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    mac: None,
                    prefix: 64,
                    mode: LanRouteMode::NextHop {
                        next_hop_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                    },
                },
            );
            service.refresh_reachable_local_ipv6_addrs(&routes);
            drop(routes);

            assert_eq!(
                service.load_reachable_local_ipv6_addrs().as_ref(),
                &vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))]
            );
        });
    }

    #[test]
    fn remove_ipv6_lan_route_by_key_state_update_keeps_other_routes_for_same_iface() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let key_a = LanIPv6RouteKey { iface_name: "lan0".to_string(), subnet_index: 0 };
            let key_b = LanIPv6RouteKey { iface_name: "lan0".to_string(), subnet_index: 1 };
            let route_a = ipv6_lan_route(
                1,
                "lan0",
                Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1),
                64,
                LanRouteMode::Reachable,
            );
            let route_b = ipv6_lan_route(
                1,
                "lan0",
                Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1),
                64,
                LanRouteMode::Reachable,
            );

            {
                let mut routes = service.ipv6_lan_ifaces.write().await;
                let update_a = service.upsert_ipv6_lan_route_by_key(
                    &mut routes,
                    key_a.clone(),
                    route_a.clone(),
                );
                let update_b = service.upsert_ipv6_lan_route_by_key(
                    &mut routes,
                    key_b.clone(),
                    route_b.clone(),
                );

                assert!(matches!(update_a, Ipv6LanRouteUpdate::Changed { removed: None, .. }));
                assert!(matches!(update_b, Ipv6LanRouteUpdate::Changed { removed: None, .. }));

                let removed = service.remove_ipv6_lan_route_by_key_inner(&mut routes, &key_a);

                assert_eq!(removed, Some(route_a));
                assert!(!routes.contains_key(&key_a));
                assert_eq!(routes.get(&key_b), Some(&route_b));
            }
            assert_eq!(
                service.load_reachable_local_ipv6_addrs().as_ref(),
                &vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1))]
            );
        });
    }

    #[test]
    fn upsert_and_remove_ipv4_lan_routes_for_same_owner_refresh_reachable_local_snapshots() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let owner = "lan0-static";
            let route_a = ipv4_lan_route(
                2,
                "lan0",
                Ipv4Addr::new(192, 168, 1, 1),
                24,
                LanRouteMode::Reachable,
            );
            let route_b =
                ipv4_lan_route(2, "lan0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable);

            {
                let mut routes = service.ipv4_lan_ifaces.write().await;
                let update_a =
                    service.upsert_ipv4_lan_routes_for_owner(&mut routes, owner, route_a.clone());
                let update_b =
                    service.upsert_ipv4_lan_routes_for_owner(&mut routes, owner, route_b.clone());

                assert!(
                    matches!(update_a, Ipv4LanBucketUpdate::Changed { ref removed, .. } if removed.is_empty())
                );
                assert!(
                    matches!(update_b, Ipv4LanBucketUpdate::Changed { ref removed, .. } if removed.is_empty())
                );
                assert_eq!(routes.get(owner), Some(&vec![route_a.clone(), route_b.clone()]));
            }
            assert_eq!(
                service.load_reachable_local_ipv4_addrs().as_ref(),
                &vec![
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                ]
            );

            {
                let mut routes = service.ipv4_lan_ifaces.write().await;
                let removed = service.remove_ipv4_lan_routes_for_owner(&mut routes, owner);

                assert_eq!(removed, Some(vec![route_a, route_b]));
                assert!(!routes.contains_key(owner));
            }
            assert!(service.load_reachable_local_ipv4_addrs().is_empty());
        });
    }

    #[test]
    fn reconcile_ipv4_lan_bucket_replaces_same_subnet_and_keeps_other_routes() {
        let mut bucket = vec![
            ipv4_lan_route(1, "lan0", Ipv4Addr::new(192, 168, 1, 1), 24, LanRouteMode::Reachable),
            ipv4_lan_route(1, "lan0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable),
        ];
        let replacement =
            ipv4_lan_route(2, "lan0", Ipv4Addr::new(192, 168, 1, 254), 24, LanRouteMode::Reachable);

        let update = reconcile_ipv4_lan_bucket(&mut bucket, replacement.clone());

        assert!(matches!(
            update,
            Ipv4LanBucketUpdate::Changed { ref removed, ref added }
                if removed
                    == &vec![ipv4_lan_route(
                        1,
                        "lan0",
                        Ipv4Addr::new(192, 168, 1, 1),
                        24,
                        LanRouteMode::Reachable
                    )]
                    && added == &replacement
        ));
        assert_eq!(
            bucket,
            vec![
                ipv4_lan_route(1, "lan0", Ipv4Addr::new(10, 0, 0, 1), 24, LanRouteMode::Reachable),
                replacement,
            ]
        );
    }

    #[test]
    fn reconcile_ipv4_lan_bucket_returns_noop_for_identical_entry() {
        let existing =
            ipv4_lan_route(1, "lan0", Ipv4Addr::new(192, 168, 1, 1), 24, LanRouteMode::Reachable);
        let mut bucket = vec![existing.clone()];

        let update = reconcile_ipv4_lan_bucket(&mut bucket, existing.clone());

        assert!(matches!(update, Ipv4LanBucketUpdate::Noop));
        assert_eq!(bucket, vec![existing]);
    }

    #[test]
    fn refresh_reachable_local_ipv4_addrs_flattens_owner_buckets() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let mut routes = service.ipv4_lan_ifaces.write().await;
            routes.insert(
                "docker-network".to_string(),
                vec![
                    ipv4_lan_route(
                        10,
                        "br0",
                        Ipv4Addr::new(172, 18, 0, 1),
                        16,
                        LanRouteMode::Reachable,
                    ),
                    ipv4_lan_route(
                        10,
                        "br0",
                        Ipv4Addr::new(172, 19, 0, 1),
                        16,
                        LanRouteMode::Reachable,
                    ),
                ],
            );
            routes.insert(
                "iface".to_string(),
                vec![ipv4_lan_route(
                    2,
                    "lan0",
                    Ipv4Addr::new(192, 168, 1, 1),
                    24,
                    LanRouteMode::Reachable,
                )],
            );

            service.refresh_reachable_local_ipv4_addrs(&routes);
            drop(routes);

            assert_eq!(
                service.load_reachable_local_ipv4_addrs().as_ref(),
                &vec![
                    IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1)),
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                ]
            );
        });
    }

    #[test]
    fn local_dns_answer_provider_loads_snapshots_directly() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let mut routes = service.ipv4_lan_ifaces.write().await;
            routes.insert(
                "lan0".to_string(),
                vec![ipv4_lan_route(
                    2,
                    "lan0",
                    Ipv4Addr::new(192, 168, 1, 1),
                    24,
                    LanRouteMode::Reachable,
                )],
            );
            service.refresh_reachable_local_ipv4_addrs(&routes);
            drop(routes);

            assert_eq!(
                service.load_local_answer_addrs(RecordType::A).as_ref(),
                &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]
            );
        });
    }

    #[test]
    fn local_dns_answer_provider_loads_ifindex_specific_snapshot() {
        run_async_test(async {
            let (_tx, service) = test_used_ip_route().await;
            let mut routes = service.ipv4_lan_ifaces.write().await;
            routes.insert(
                "lan0".to_string(),
                vec![
                    ipv4_lan_route(
                        2,
                        "lan0",
                        Ipv4Addr::new(192, 168, 1, 1),
                        24,
                        LanRouteMode::Reachable,
                    ),
                    ipv4_lan_route(
                        7,
                        "lan1",
                        Ipv4Addr::new(192, 168, 2, 1),
                        24,
                        LanRouteMode::Reachable,
                    ),
                ],
            );
            service.refresh_reachable_local_ipv4_addrs(&routes);
            drop(routes);

            assert_eq!(
                service.load_local_answer_addrs_for_ifindex(RecordType::A, 7).as_ref(),
                &vec![IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))]
            );
            assert!(service.load_local_answer_addrs_for_ifindex(RecordType::A, 99).is_empty());
        });
    }

    // ── collect_target_refresh_result ──────────────────────────────

    fn flow_config(flow_id: u32, enable: bool, targets: Vec<WeightedFlowTarget>) -> FlowConfig {
        FlowConfig {
            id: Uuid::nil(),
            enable,
            flow_id,
            flow_match_rules: vec![],
            flow_targets: targets,
            remark: String::new(),
            update_at: 0.0,
        }
    }

    fn iface_target(name: &str, weight: u32) -> WeightedFlowTarget {
        WeightedFlowTarget::new(FlowTarget::Interface { name: name.to_string() }, weight)
    }

    fn netns_target(container_name: &str, weight: u32) -> WeightedFlowTarget {
        WeightedFlowTarget::new(
            FlowTarget::Netns { container_name: container_name.to_string() },
            weight,
        )
    }

    #[test]
    fn collect_refresh_enabled_flow_with_matching_targets() {
        let mut wan_infos = WanRoutesByOwner::new();
        wan_infos
            .insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));
        wan_infos.insert("wan1".to_string(), ipv4_wan_route("wan1", Ipv4Addr::new(203, 0, 113, 1)));

        let configs =
            vec![flow_config(5, true, vec![iface_target("wan0", 3), iface_target("wan1", 1)])];

        let result = collect_target_refresh_result(&configs, &wan_infos);

        let targets = result.get(&5).expect("flow_id 5 should be present");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].1, 3); // weight preserved
        assert_eq!(targets[1].1, 1);
        assert_eq!(targets[0].0.iface_name, "wan0");
        assert_eq!(targets[1].0.iface_name, "wan1");
    }

    #[test]
    fn collect_refresh_disabled_flow_yields_empty() {
        let mut wan_infos = WanRoutesByOwner::new();
        wan_infos
            .insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

        let configs = vec![flow_config(5, false, vec![iface_target("wan0", 1)])];

        let result = collect_target_refresh_result(&configs, &wan_infos);

        let targets = result.get(&5).expect("flow_id 5 should be present");
        assert!(targets.is_empty());
    }

    #[test]
    fn collect_refresh_enabled_flow_with_unresolved_targets_yields_empty() {
        let wan_infos = WanRoutesByOwner::new(); // no routes registered

        let configs = vec![flow_config(5, true, vec![iface_target("missing_wan", 2)])];

        let result = collect_target_refresh_result(&configs, &wan_infos);

        let targets = result.get(&5).expect("flow_id 5 should be present");
        assert!(targets.is_empty());
    }

    #[test]
    fn collect_refresh_partial_match_keeps_only_resolved() {
        let mut wan_infos = WanRoutesByOwner::new();
        wan_infos
            .insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

        let configs = vec![flow_config(
            5,
            true,
            vec![iface_target("wan0", 3), iface_target("missing_wan", 1)],
        )];

        let result = collect_target_refresh_result(&configs, &wan_infos);

        let targets = result.get(&5).expect("flow_id 5 should be present");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0.iface_name, "wan0");
        assert_eq!(targets[0].1, 3);
    }

    #[test]
    fn collect_refresh_netns_target_resolves_by_container_name() {
        let mut wan_infos = WanRoutesByOwner::new();
        wan_infos.insert("ns0".to_string(), ipv4_wan_route("ns0", Ipv4Addr::new(10, 0, 0, 1)));

        let configs = vec![flow_config(3, true, vec![netns_target("ns0", 5)])];

        let result = collect_target_refresh_result(&configs, &wan_infos);

        let targets = result.get(&3).expect("flow_id 3 should be present");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0.iface_name, "ns0");
        assert_eq!(targets[0].1, 5);
    }

    #[test]
    fn collect_refresh_multiple_flows_independent() {
        let mut wan_infos = WanRoutesByOwner::new();
        wan_infos
            .insert("wan0".to_string(), ipv4_wan_route("wan0", Ipv4Addr::new(198, 51, 100, 1)));

        let configs = vec![
            flow_config(1, true, vec![iface_target("wan0", 2)]),
            flow_config(2, false, vec![iface_target("wan0", 1)]),
            flow_config(3, true, vec![iface_target("missing", 1)]),
        ];

        let result = collect_target_refresh_result(&configs, &wan_infos);

        assert_eq!(result.get(&1).unwrap().len(), 1);
        assert!(result.get(&2).unwrap().is_empty());
        assert!(result.get(&3).unwrap().is_empty());
    }
}
