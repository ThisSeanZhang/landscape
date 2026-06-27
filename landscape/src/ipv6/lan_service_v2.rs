use landscape_common::client::CallerLookupMatch;
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
use landscape_common::service::WatchService;
use landscape_database::enrolled_device::repository::EnrolledDeviceRepository;
use landscape_database::lan_ipv6_v2::repository::LanIPv6V2ServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::dhcp_server::v6_v2::Ipv6ServerStatus;
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
            let status = Arc::new(Mutex::new(Ipv6ServerStatus::new()));
            {
                let mut s = status.lock().await;
                s.upate_prefix(&config.config.prefix_groups, &self.prefix_map);
            }
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
        let store_for_prefix = store_service.lan_ipv6_v2_service_store();
        let prefix_map_for_loop = prefix_map.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = prefix_update_tx.recv() => {
                        if let Ok(IAPrefixEvent::Updated { iface_name }) = msg {
                            // TODO: build WAN iface → LAN iface dependency index
                            // Currently refreshes prefix_state for all started LAN services
                            for entry in status_map.iter() {
                                let lan_iface = entry.key().clone();
                                if let Ok(Some(cfg)) =
                                    store_for_prefix.find_by_id(lan_iface).await
                                {
                                    let status = entry.value();
                                    let mut s = status.lock().await;
                                    s.upate_prefix(
                                        &cfg.config.prefix_groups,
                                        &prefix_map_for_loop,
                                    );
                                }
                            }
                            let _ = iface_name;
                        }
                    },
                    msg = device_reader.recv() => {
                        // using msg
                        // TODO get lock
                        // status.upate_device();
                        let _ = msg;
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
        // TODO
        None
    }

    pub async fn get_assigned_ips(&self) -> HashMap<String, IPv6NAInfo> {
        let result = HashMap::new();

        // TODO

        result
    }

    pub async fn get_dhcpv6_assigned_by_iface_name(
        &self,
        iface_name: String,
    ) -> Option<DHCPv6OfferInfo> {
        // TODO
        None
    }

    pub async fn get_dhcpv6_assigned(&self) -> HashMap<String, DHCPv6OfferInfo> {
        let result = HashMap::new();
        // TODO
        result
    }

    pub async fn resolve_client_match_by_ipv6(&self, ip: Ipv6Addr) -> Option<CallerLookupMatch> {
        // TODO

        None
    }

    pub async fn get_device_ipv6_map(&self) -> HashMap<Uuid, Ipv6Addr> {
        let result = HashMap::new();

        // TODO

        result
    }
}

fn extract_binding_ifaces_v6(_event: &EnrolledDeviceEvent) -> HashSet<String> {
    let set = HashSet::new();
    // TODO
    set
}
