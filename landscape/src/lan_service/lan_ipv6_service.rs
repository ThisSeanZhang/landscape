use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::event::hub::iface::IfaceObserverAction;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IAPrefixEvent, IAPrefixEventReader,
    IPv6AssignEvent, IPv6AssignEventSender, IPv6AssignInfo, IfaceEventReader,
};
use landscape_common::lan_service::lan_ipv6::DHCPv6OfferInfo;
use landscape_common::lan_service::lan_ipv6::IPv6NAInfo;
use landscape_common::lan_service::lan_ipv6::{IPv6ServiceMode, LanIPv6ServiceConfigV2};
use landscape_common::net::MacAddr;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::sys_service::client::{CallerLookupMatch, CallerLookupSource};
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;
use landscape_database::enrolled_device::repository::EnrolledDeviceRepository;
use landscape_database::lan_ipv6_v2::repository::LanIPv6V2ServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex};
use uuid::Uuid;

use super::lan_ipv6_server::{
    server::start_ipv6_lan_server, AddrSource, Ipv6LanReplyParams, Ipv6ServerStatus,
};
use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;
use dashmap::DashMap;
use landscape_common::lan_service::mac_binding::MacBindingDataplane;

use landscape_ebpf::chain::ip6_dao_event::{Ip6DaoEvent, Ip6DaoEventSource};

mod mac_link_map;
pub use self::mac_link_map::{start_periodic_scan, MacLinkMapCache};

#[derive(Clone)]
pub struct LanIPv6Service {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
    enrolled_device_store: EnrolledDeviceRepository,
    ipv6_assign_sender: IPv6AssignEventSender,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
    status_map: Arc<DashMap<String, Arc<Mutex<Ipv6ServerStatus>>>>,
    per_iface_txs: Arc<DashMap<String, watch::Sender<()>>>,
    mac_link_map_cache: Arc<MacLinkMapCache>,
    mac_binding: Arc<dyn MacBindingDataplane>,
    /// Per-ifindex channel to the DAD learning consumer of each running server.
    dao_event_senders: Arc<DashMap<u32, mpsc::Sender<Ip6DaoEvent>>>,
}

impl LanIPv6Service {
    pub fn new(
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        enrolled_device_store: EnrolledDeviceRepository,
        ipv6_assign_sender: IPv6AssignEventSender,
        mac_link_map_cache: Arc<MacLinkMapCache>,
        mac_binding: Arc<dyn MacBindingDataplane>,
    ) -> Self {
        Self {
            route_service,
            prefix_map,
            enrolled_device_store,
            ipv6_assign_sender,
            device_id_map: Arc::new(DashMap::new()),
            status_map: Arc::new(DashMap::new()),
            per_iface_txs: Arc::new(DashMap::new()),
            mac_link_map_cache,
            mac_binding,
            dao_event_senders: Arc::new(DashMap::new()),
        }
    }
}

/// Inner DAD dispatch loop: forwards events from `rx` to the per-iface
/// senders registered in `dao_event_senders`. Runs until the channel closes.
async fn run_dad_dispatcher(
    mut rx: mpsc::Receiver<Ip6DaoEvent>,
    dao_event_senders: Arc<DashMap<u32, mpsc::Sender<Ip6DaoEvent>>>,
) {
    while let Some(ev) = rx.recv().await {
        match dao_event_senders.get(&ev.ifindex) {
            Some(tx) => {
                if let Err(error) = tx.try_send(ev) {
                    tracing::debug!(
                        "LAN IPv6 server for ifindex {} {error:?}; dropping DAD event",
                        ev.ifindex
                    );
                }
            }
            None => {
                tracing::debug!(
                    "no LAN IPv6 server for ifindex {}; dropping DAD event",
                    ev.ifindex
                );
            }
        }
    }
}

/// Supervisor keeping the per-ifindex DAD dispatcher and the ringbuf consumer
/// alive: on task death it re-attaches a fresh channel / rebuilds the consumer.
async fn supervise_dad_dispatcher(
    source: Arc<Ip6DaoEventSource>,
    dao_event_senders: Arc<DashMap<u32, mpsc::Sender<Ip6DaoEvent>>>,
) {
    let shutdown = source.cancelled();
    loop {
        let (tx, rx) = mpsc::channel(256);
        source.attach_channel(tx);
        let senders = dao_event_senders.clone();
        let dispatch = tokio::spawn(run_dad_dispatcher(rx, senders));
        let consumer_died = source.consumer_died_token();
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("ip6_dao_event dispatcher supervisor shutting down");
                break;
            }
            _ = consumer_died.cancelled() => {
                tracing::warn!(
                    "ip6_dao_event ringbuf consumer task exited; rebuilding with a fresh consumer"
                );
                if shutdown.is_cancelled() {
                    break;
                }
                if let Err(e) = source.restart_consumer() {
                    tracing::error!(
                        "failed to restart ip6_dao_event ringbuf consumer: {e}; retrying in 1s"
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            result = dispatch => {
                match result {
                    Ok(()) => {
                        tracing::warn!(
                            "ip6_dao_event dispatcher stopped; restarting with a fresh channel"
                        );
                    }
                    Err(join) => {
                        tracing::error!("ip6_dao_event dispatcher panicked: {join}; restarting");
                    }
                }
                if shutdown.is_cancelled() {
                    break;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for LanIPv6Service {
    type Config = LanIPv6ServiceConfigV2;

    async fn start(&self, config: LanIPv6ServiceConfigV2) -> WatchService {
        let service_status = WatchService::new();
        if config.enable {
            service_status.just_change_status(ServiceStatus::Staring);

            let iface = match get_iface_by_name(&config.iface_name).await {
                Some(i) => i,
                None => {
                    tracing::error!("interface {} not found", config.iface_name);
                    service_status.just_change_status(ServiceStatus::Failed);
                    return service_status;
                }
            };

            let mac_addr = match iface.mac {
                Some(m) => m,
                None => {
                    tracing::error!("no MAC address for interface {}", config.iface_name);
                    service_status.just_change_status(ServiceStatus::Failed);
                    return service_status;
                }
            };

            let na_config = config.config.dhcpv6.as_ref().and_then(|d| d.ia_na.clone());
            let pd_config = config.config.dhcpv6.as_ref().and_then(|d| d.ia_pd.clone());
            let devices = self
                .enrolled_device_store
                .find_ipv6_bindings(config.iface_name.clone())
                .await
                .unwrap_or_default();

            for d in &devices {
                self.device_id_map.insert(d.mac, d.id);
            }

            // ── Mode handling ──
            let mode = config.config.mode;
            let dhcpv6_enabled = config.config.dhcpv6.as_ref().is_some_and(|c| c.enable);

            match mode {
                IPv6ServiceMode::Slaac => {
                    if dhcpv6_enabled {
                        tracing::warn!("Slaac mode selected but DHCPv6 enabled; disabling DHCPv6");
                    }
                }
                IPv6ServiceMode::Stateful | IPv6ServiceMode::SlaacDhcpv6 => {
                    if !dhcpv6_enabled {
                        tracing::error!("{:?} mode but DHCPv6 not enabled", mode);
                        service_status.just_change_status(ServiceStatus::Failed);
                        return service_status;
                    }
                }
            }

            // ── Reconfigure channel ──
            let (reconf_tx, reconf_rx) = mpsc::unbounded_channel();

            // ── Create status ──
            let status = Arc::new(Mutex::new(Ipv6ServerStatus::new(
                na_config.clone(),
                pd_config.clone(),
                devices,
                reconf_tx,
            )));
            // ── Reply params ──
            let preferred_lifetime = config.config.preferred_lifetime();
            let valid_lifetime = config.config.valid_lifetime();
            let icmp_ad_interval = config.config.icmp_ad_interval();

            let mut ra_flags_raw: u8 = config.config.ra_flag.into();
            let ra_autonomous = mode != IPv6ServiceMode::Stateful;
            // M flag: managed address configuration
            if mode == IPv6ServiceMode::Slaac {
                ra_flags_raw &= !0x80; // clear M flag
            } else {
                ra_flags_raw |= 0x80; // set M flag
            }

            let params = Ipv6LanReplyParams {
                preferred_lifetime,
                valid_lifetime,
                ra_flags: ra_flags_raw,
                ra_autonomous,
            };

            // ── Prefix change notification channel ──
            let (prefix_tx, prefix_rx) = watch::channel(());
            self.per_iface_txs.insert(config.iface_name.clone(), prefix_tx);

            // ── Store status ──
            let store_key = config.iface_name.clone();
            self.status_map.insert(store_key, status.clone());

            // ── Spawn server ──
            let svc_status = service_status.clone();
            let ipv6_assign_sender = self.ipv6_assign_sender.clone();
            let route_service = self.route_service.clone();
            let prefix_groups = config.config.prefix_groups.clone();
            let prefix_map = self.prefix_map.clone();
            let device_id_map = self.device_id_map.clone();
            let mac_link_cache = self.mac_link_map_cache.clone();
            let mac_binding = self.mac_binding.clone();
            // Bounded: the server consumer is rate-limited (32 probes/s with
            // a 1024-entry probe queue), so under a DAD NS flood the channel
            // drops events (best-effort) instead of growing without bound.
            let (dao_tx, dao_rx) = mpsc::channel(1024);
            self.dao_event_senders.insert(iface.index, dao_tx.clone());
            let dao_event_senders = self.dao_event_senders.clone();
            let ifindex = iface.index;
            tokio::spawn(async move {
                let _ = start_ipv6_lan_server(
                    ifindex,
                    config.iface_name.clone(),
                    mac_addr,
                    svc_status,
                    icmp_ad_interval,
                    &ipv6_assign_sender,
                    status,
                    mac_link_cache,
                    prefix_groups,
                    prefix_map,
                    prefix_rx,
                    params,
                    route_service,
                    device_id_map,
                    reconf_rx,
                    dao_rx,
                    mac_binding,
                )
                .await;
                // Only remove the channel we inserted. On a service restart a
                // newer server may have already replaced this ifindex's entry;
                // deleting it would close the new server's DAD channel.
                dao_event_senders.remove_if(&ifindex, |_, v| v.same_channel(&dao_tx));
            });
        }

        service_status
    }
}

#[derive(Clone)]
pub struct LanIPv6ManagerService {
    store: LanIPv6V2ServiceRepository,
    service: ServiceManager<LanIPv6Service>,
    server_starter: LanIPv6Service,
    #[allow(dead_code)]
    mac_link_map_cache: Arc<MacLinkMapCache>,
    /// Keeps the global DAD ringbuf consumer alive (Arc refcount only).
    #[allow(dead_code)]
    dao_event_source: Option<Arc<Ip6DaoEventSource>>,
}

impl ControllerService for LanIPv6ManagerService {
    type Id = String;
    type Config = LanIPv6ServiceConfigV2;
    type DatabseAction = LanIPv6V2ServiceRepository;
    type H = LanIPv6Service;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl LanIPv6ManagerService {
    pub async fn save_config(
        &self,
        config: LanIPv6ServiceConfigV2,
    ) -> Result<LanIPv6ServiceConfigV2, landscape_common::lan_service::lan_ipv6::LanIPv6Error> {
        let saved = self.store.checked_set_with_global_validation(config).await?;
        self.service.update_service_wait(saved.clone()).await;
        Ok(saved)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        mut device_reader: EnrolledDeviceEventReader,
        mut prefix_update_tx: IAPrefixEventReader,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        ipv6_assign_sender: IPv6AssignEventSender,
        mac_binding: Arc<dyn MacBindingDataplane>,
        dao_event_source: Option<Arc<Ip6DaoEventSource>>,
    ) -> Self {
        let store = store_service.lan_ipv6_v2_service_store();
        let enrolled_device_store = store_service.enrolled_device_store();
        let prefix_map_for_starter = prefix_map.clone();

        let mac_link_map_cache = Arc::new(MacLinkMapCache::new());
        start_periodic_scan(&mac_link_map_cache, 60);

        let server_starter = LanIPv6Service::new(
            route_service,
            prefix_map_for_starter,
            enrolled_device_store,
            ipv6_assign_sender,
            mac_link_map_cache.clone(),
            mac_binding,
        );

        // ── Global DAD NS learning consumer ──
        // One process-wide ringbuf consumer, dispatching events by ifindex to
        // the per-iface server channels registered in `dao_event_senders`. A
        // supervisor keeps the dispatcher alive: if the dispatch task ever
        // dies, it attaches a fresh channel to the source and restarts.
        let dao_event_senders = server_starter.dao_event_senders.clone();
        if let Some(source) = dao_event_source.clone() {
            spawn_task(
                task_label::task::EBPF_IP6_DAO_DISPATCHER,
                supervise_dad_dispatcher(source, dao_event_senders),
            );
        }
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} LAN IPv6 service");
                        let service_config = if let Some(service_config) =
                            store.find_by_id(iface_name.clone()).await.unwrap()
                        {
                            service_config
                        } else {
                            continue;
                        };

                        let _ = service_clone.update_service(service_config).await;
                    }
                    IfaceObserverAction::Down(_) => {}
                }
            }
        });

        let status_map = server_starter.status_map.clone();
        let device_id_map = server_starter.device_id_map.clone();
        let per_iface_txs = server_starter.per_iface_txs.clone();
        let ipv6_assign_sender = server_starter.ipv6_assign_sender.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = prefix_update_tx.recv() => {
                        if matches!(
                            msg,
                            Ok(IAPrefixEvent::Updated { .. } | IAPrefixEvent::Expired { .. })
                        ) {
                            // Notify all LAN services that prefix map changed.
                            // Each server will recompute subnets and apply diff.
                            for entry in per_iface_txs.iter() {
                                let _ = entry.value().send(());
                            }
                        }
                    },
                    msg = device_reader.recv() => {
                        let event = match msg {
                            Ok(e) => e,
                            Err(_) => break,
                        };
                        match &event {
                            EnrolledDeviceEvent::Updated { old, new } => {
                                if let Some(d) = old.as_ref() {
                                    if d.mac != new.mac {
                                        device_id_map.remove(&d.mac);
                                    }
                                }
                                device_id_map.insert(new.mac, new.id);
                                let new_iface = new.iface_name.as_deref();
                                let old_iface = old.as_ref().and_then(|d| d.iface_name.as_deref());
                                let global = new_iface.is_none() && old_iface.is_none();
                                let entries: Vec<_> = status_map
                                    .iter()
                                    .map(|e| (e.key().clone(), e.value().clone()))
                                    .collect();
                                for (name, status) in entries {
                                    if !global && Some(name.as_str()) != new_iface && Some(name.as_str()) != old_iface {
                                        continue;
                                    }
                                    let mut s = status.lock().await;
                                    if let Some(d) = old.as_ref() {
                                        let r = s.update_device_binding(d.mac, None);
                                        s.trigger_reconfigure_for_changes(&r);
                                        if !global {
                                            let ips = s.all_ips_for_mac(&d.mac);
                                            let _ = ipv6_assign_sender.try_send(
                                                IPv6AssignEvent::Flush(IPv6AssignInfo {
                                                    iface_name: name.clone(),
                                                    mac: d.mac,
                                                    ips,
                                                    device_id: Some(d.id),
                                                }),
                                            );
                                        }
                                    }
                                    let r = s.update_device_binding(new.mac, new.ipv6);
                                    s.trigger_reconfigure_for_changes(&r);
                                    if !global {
                                        let ips = s.all_ips_for_mac(&new.mac);
                                        let _ = ipv6_assign_sender.try_send(
                                            IPv6AssignEvent::Flush(IPv6AssignInfo {
                                                iface_name: name.clone(),
                                                mac: new.mac,
                                                ips,
                                                device_id: Some(new.id),
                                            }),
                                        );
                                    }
                                }
                            }
                            EnrolledDeviceEvent::Deleted { old } => {
                                device_id_map.remove(&old.mac);
                                let global = old.iface_name.is_none();
                                let entries: Vec<_> = status_map
                                    .iter()
                                    .map(|e| (e.key().clone(), e.value().clone()))
                                    .collect();
                                for (name, status) in entries {
                                    if !global && old.iface_name.as_deref() != Some(name.as_str()) {
                                        continue;
                                    }
                                    let mut s = status.lock().await;
                                    let r = s.update_device_binding(old.mac, None);
                                    s.trigger_reconfigure_for_changes(&r);
                                    if !global {
                                        let ips = s.all_ips_for_mac(&old.mac);
                                        let _ =
                                            ipv6_assign_sender.try_send(IPv6AssignEvent::Flush(
                                                IPv6AssignInfo {
                                                    iface_name: name.clone(),
                                                    mac: old.mac,
                                                    ips,
                                                    device_id: Some(old.id),
                                                },
                                            ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let store = store_service.lan_ipv6_v2_service_store();

        Self {
            service,
            store,
            server_starter,
            mac_link_map_cache,
            dao_event_source,
        }
    }

    pub async fn refresh_iface_service(&self, iface_name: String) {
        let Some(service_config) = self.get_config_by_name(iface_name).await else {
            return;
        };
        let _ = self.get_service().update_service(service_config).await;
    }

    pub async fn get_assigned_ips_by_iface_name(&self, iface_name: String) -> Option<IPv6NAInfo> {
        let status = self.server_starter.status_map.get(&iface_name)?.value().clone();
        let lock = status.lock().await;
        Some(lock.to_ipv6_na_info())
    }

    pub async fn get_assigned_ips(&self) -> HashMap<String, IPv6NAInfo> {
        let statuses: Vec<(String, _)> = self
            .server_starter
            .status_map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        let mut result = HashMap::new();
        for (iface, status) in statuses {
            let lock = status.lock().await;
            result.insert(iface, lock.to_ipv6_na_info());
        }
        result
    }

    pub async fn get_dhcpv6_assigned_by_iface_name(
        &self,
        iface_name: String,
    ) -> Option<DHCPv6OfferInfo> {
        let status = self.server_starter.status_map.get(&iface_name)?.value().clone();
        let lock = status.lock().await;
        Some(lock.to_dhcpv6_offer_info())
    }

    pub async fn get_dhcpv6_assigned(&self) -> HashMap<String, DHCPv6OfferInfo> {
        let statuses: Vec<(String, _)> = self
            .server_starter
            .status_map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        let mut result = HashMap::new();
        for (iface, status) in statuses {
            let lock = status.lock().await;
            result.insert(iface, lock.to_dhcpv6_offer_info());
        }
        result
    }

    pub async fn resolve_client_match_by_ipv6(&self, ip: Ipv6Addr) -> Option<CallerLookupMatch> {
        let statuses: Vec<(String, _)> = self
            .server_starter
            .status_map
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        for (iface_name, status) in statuses {
            let lock = status.lock().await;
            if let Some(addr) = lock.lookup_by_ip(ip) {
                return Some(CallerLookupMatch {
                    iface_name,
                    mac: addr.mac,
                    hostname: addr.hostname,
                    source: match addr.source {
                        AddrSource::Slaac => CallerLookupSource::Ipv6Ra,
                        AddrSource::Dhcpv6Na => CallerLookupSource::DhcpV6,
                    },
                });
            }
        }
        None
    }

    pub async fn get_device_ipv6_map(&self) -> HashMap<Uuid, Ipv6Addr> {
        let device_ids: Vec<(MacAddr, Uuid)> =
            self.server_starter.device_id_map.iter().map(|e| (*e.key(), *e.value())).collect();
        let statuses: Vec<_> =
            self.server_starter.status_map.iter().map(|e| e.value().clone()).collect();
        let mut result = HashMap::new();
        for (mac, dev_id) in &device_ids {
            for status_arc in &statuses {
                let lock = status_arc.lock().await;
                if let Some(ip) = lock.lookup_ip_by_mac(mac) {
                    result.insert(*dev_id, ip);
                    break;
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(ifindex: u32, ip: u8) -> Ip6DaoEvent {
        Ip6DaoEvent { ifindex, ip: [ip; 16], mac: [1; 6], __pad: [0; 6] }
    }

    #[tokio::test]
    async fn dad_dispatcher_forwards_to_matching_ifindex() {
        let senders: Arc<DashMap<u32, mpsc::Sender<Ip6DaoEvent>>> = Arc::new(DashMap::new());
        let (tx, mut rx) = mpsc::channel(8);
        senders.insert(6, tx);
        let (in_tx, in_rx) = mpsc::channel(8);

        let dispatch = tokio::spawn(run_dad_dispatcher(in_rx, senders));
        in_tx.send(sample_event(6, 0xfd)).await.expect("send event");
        drop(in_tx);

        let got = rx.recv().await.expect("event forwarded to matching ifindex");
        assert_eq!(got.ifindex, 6);
        dispatch.await.expect("dispatcher exits when the input channel closes");
    }

    #[tokio::test]
    async fn dad_dispatcher_drops_unknown_ifindex() {
        let senders: Arc<DashMap<u32, mpsc::Sender<Ip6DaoEvent>>> = Arc::new(DashMap::new());
        let (in_tx, in_rx) = mpsc::channel(8);

        let dispatch = tokio::spawn(run_dad_dispatcher(in_rx, senders));
        in_tx.send(sample_event(99, 0xfd)).await.expect("send event");
        drop(in_tx);

        dispatch.await.expect("dispatcher exits when the input channel closes");
    }

    #[tokio::test]
    async fn dad_dispatcher_survives_closed_per_iface_channel() {
        // A per-iface receiver that died (service restart race) must not kill
        // the dispatch loop: later events for live ifindexes still arrive.
        let senders: Arc<DashMap<u32, mpsc::Sender<Ip6DaoEvent>>> = Arc::new(DashMap::new());
        let (dead_tx, _dead_rx) = mpsc::channel::<Ip6DaoEvent>(8);
        senders.insert(6, dead_tx);
        let (live_tx, mut live_rx) = mpsc::channel::<Ip6DaoEvent>(8);
        senders.insert(7, live_tx);
        let (in_tx, in_rx) = mpsc::channel(8);

        let dispatch = tokio::spawn(run_dad_dispatcher(in_rx, senders));
        in_tx.send(sample_event(6, 0xfd)).await.expect("send event to dead channel");
        in_tx.send(sample_event(7, 0xfe)).await.expect("send event to live channel");
        drop(in_tx);

        let got = live_rx.recv().await.expect("event after closed-channel send still forwarded");
        assert_eq!(got.ifindex, 7);
        dispatch.await.expect("dispatcher exits when the input channel closes");
    }
}
