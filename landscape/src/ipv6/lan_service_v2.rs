use landscape_common::client::{CallerLookupMatch, CallerLookupSource};
use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IAPrefixEvent, IAPrefixEventReader,
    IPv6AssignEventSender, IfaceEventReader,
};
use landscape_common::ipv6::lan::LanIPv6ServiceConfigV2;
use landscape_common::ipv6_pd::IAPrefixMap;
use landscape_common::lan_services::ipv6_ra::IPv6NAInfo;
use landscape_common::net::MacAddr;
use landscape_common::observer::IfaceObserverAction;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_database::enrolled_device::repository::EnrolledDeviceRepository;
use landscape_database::lan_ipv6_v2::repository::LanIPv6V2ServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::dhcp_server::v6_v2::{
    server::start_ipv6_lan_server, AddrSource, Ipv6LanReplyParams, Ipv6ServerStatus,
};
use crate::iface::get_iface_by_name;
use crate::route::IpRouteService;
use dashmap::DashMap;

#[derive(Clone)]
pub struct LanIPv6Service {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
    enrolled_device_store: EnrolledDeviceRepository,
    ipv6_assign_sender: IPv6AssignEventSender,
    device_id_map: Arc<DashMap<MacAddr, Uuid>>,
    status_map: Arc<DashMap<String, Arc<Mutex<Ipv6ServerStatus>>>>,
}

impl LanIPv6Service {
    pub fn new(
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        enrolled_device_store: EnrolledDeviceRepository,
        ipv6_assign_sender: IPv6AssignEventSender,
    ) -> Self {
        Self {
            route_service,
            prefix_map,
            enrolled_device_store,
            ipv6_assign_sender,
            device_id_map: Arc::new(DashMap::new()),
            status_map: Arc::new(DashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for LanIPv6Service {
    type Config = LanIPv6ServiceConfigV2;

    async fn start(&self, config: LanIPv6ServiceConfigV2) -> WatchService {
        let service_status = WatchService::new();
        if config.enable {
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

            let status = Arc::new(Mutex::new(Ipv6ServerStatus::new(
                na_config.clone(),
                pd_config.clone(),
                devices,
            )));
            {
                let mut s = status.lock().await;
                s.update_prefix(&config.config.prefix_groups, &self.prefix_map);
            }

            let na_lifetimes = na_config
                .as_ref()
                .map(|c| (c.preferred_lifetime, c.valid_lifetime))
                .unwrap_or((300, 600));
            let pd_lifetimes = pd_config
                .as_ref()
                .map(|c| (c.preferred_lifetime, c.valid_lifetime))
                .unwrap_or((300, 600));
            let ra_lifetimes = config
                .config
                .prefix_groups
                .iter()
                .find_map(|g| g.ra.as_ref())
                .map(|ra| (ra.preferred_lifetime, ra.valid_lifetime))
                .unwrap_or((300, 600));
            let ra_flags: u8 = config.config.ra_flag.into();

            let params = Ipv6LanReplyParams {
                na_preferred_lifetime: na_lifetimes.0,
                na_valid_lifetime: na_lifetimes.1,
                pd_preferred_lifetime: pd_lifetimes.0,
                pd_valid_lifetime: pd_lifetimes.1,
                ra_preferred_lifetime: ra_lifetimes.0,
                ra_valid_lifetime: ra_lifetimes.1,
                ra_flags,
            };

            let dns_servers: Vec<std::net::Ipv6Addr> = Vec::new();

            let store_key = config.iface_name.clone();
            self.status_map.insert(store_key, status.clone());

            let svc_status = service_status.clone();
            let ipv6_assign_sender = self.ipv6_assign_sender.clone();
            tokio::spawn(async move {
                let _ = start_ipv6_lan_server(
                    iface.index,
                    config.iface_name.clone(),
                    mac_addr,
                    svc_status,
                    config.config.ad_interval,
                    &ipv6_assign_sender,
                    status,
                    params,
                    dns_servers,
                )
                .await;
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
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        mut device_reader: EnrolledDeviceEventReader,
        mut prefix_update_tx: IAPrefixEventReader,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        ipv6_assign_sender: IPv6AssignEventSender,
    ) -> Self {
        let store = store_service.lan_ipv6_v2_service_store();
        let enrolled_device_store = store_service.enrolled_device_store();
        let prefix_map_for_starter = prefix_map.clone();
        let server_starter = LanIPv6Service::new(
            route_service,
            prefix_map_for_starter,
            enrolled_device_store,
            ipv6_assign_sender,
        );
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
        let store_for_prefix = store_service.lan_ipv6_v2_service_store();
        let prefix_map_for_loop = prefix_map.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = prefix_update_tx.recv() => {
                        if let Ok(IAPrefixEvent::Updated { iface_name }) = msg {
                            // TODO: build WAN iface → LAN iface dependency index
                            // Currently refreshes prefix_state for all started LAN services
                            let entries: Vec<_> = status_map
                                .iter()
                                .map(|e| (e.key().clone(), e.value().clone()))
                                .collect();
                            for (lan_iface, status) in entries {
                                if let Ok(Some(cfg)) =
                                    store_for_prefix.find_by_id(lan_iface).await
                                {
                                    let mut s = status.lock().await;
                                    s.update_prefix(
                                        &cfg.config.prefix_groups,
                                        &prefix_map_for_loop,
                                    );
                                }
                            }
                            let _ = iface_name;
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
                                    if d.mac != new.mac || new.ipv6.is_none() {
                                        device_id_map.remove(&d.mac);
                                    }
                                }
                                if new.ipv6.is_some() {
                                    device_id_map.insert(new.mac, new.id);
                                }
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
                                        s.update_device_binding(d.mac, None);
                                    }
                                    s.update_device_binding(new.mac, new.ipv6);
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
                                    s.update_device_binding(old.mac, None);
                                }
                            }
                        }
                    }
                }
            }
        });

        let store = store_service.lan_ipv6_v2_service_store();
        Self { service, store, server_starter }
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
