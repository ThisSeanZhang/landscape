use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use landscape_common::ipv6::ra::IPV6RAConfig;
use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::ipv6_pd::IAPrefixMap;
use landscape_common::lan_services::ipv6_ra::IPv6NAInfo;
use landscape_common::observer::IfaceObserverAction;
use landscape_common::route::LanRouteInfo;
use landscape_common::route::LanRouteMode;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::manager::ServiceManager;
use landscape_common::service::manager::ServiceStarterTrait;
use landscape_common::store::storev2::LandscapeStore;
use landscape_common::{ipv6::ra::IPV6RAServiceConfig, service::WatchService};
use landscape_database::enrolled_device::repository::EnrolledDeviceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::ra::repository::IPV6RAServiceRepository;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use crate::iface::get_iface_by_name;
use crate::ipv6::prefix::{cleanup_prefix_sources, setup_prefix_sources, PrefixSetupResult};
use crate::route::IpRouteService;

/// 控制进行路由通告
#[derive(Clone)]
pub struct IPV6RAService {
    route_service: IpRouteService,
    prefix_map: IAPrefixMap,
    iface_lease_map: Arc<RwLock<HashMap<String, Arc<RwLock<IPv6NAInfo>>>>>,
    iface_dhcpv6_map: Arc<RwLock<HashMap<String, Arc<RwLock<DHCPv6OfferInfo>>>>>,
    enrolled_device_store: EnrolledDeviceRepository,
}

impl IPV6RAService {
    pub fn new(
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
        enrolled_device_store: EnrolledDeviceRepository,
    ) -> Self {
        Self {
            route_service,
            prefix_map,
            iface_lease_map: Arc::new(RwLock::new(HashMap::new())),
            iface_dhcpv6_map: Arc::new(RwLock::new(HashMap::new())),
            enrolled_device_store,
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for IPV6RAService {
    type Config = IPV6RAServiceConfig;

    async fn start(&self, config: IPV6RAServiceConfig) -> WatchService {
        let service_status = WatchService::new();
        if config.enable {
            let route_service = self.route_service.clone();
            let prefix_map = self.prefix_map.clone();
            let status_clone = service_status.clone();
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let store_key = config.get_store_key();
                let assigned_ips = {
                    let mut write = self.iface_lease_map.write().await;
                    write
                        .entry(store_key.clone())
                        .or_insert_with(|| Arc::new(RwLock::new(IPv6NAInfo::init())))
                        .clone()
                };

                // DHCPv6 setup
                let dhcpv6_config = config.config.dhcpv6.clone();
                let dhcpv6_assigned = if dhcpv6_config.as_ref().map_or(false, |c| c.enable) {
                    let assigned = {
                        let mut write = self.iface_dhcpv6_map.write().await;
                        write
                            .entry(store_key.clone())
                            .or_insert_with(|| Arc::new(RwLock::new(DHCPv6OfferInfo::default())))
                            .clone()
                    };
                    Some(assigned)
                } else {
                    None
                };

                // Load static IPv6 bindings from enrolled devices
                let static_bindings = if dhcpv6_config.as_ref().map_or(false, |c| c.enable) {
                    match self
                        .enrolled_device_store
                        .find_dhcpv6_bindings(config.iface_name.clone())
                        .await
                    {
                        Ok(devices) => {
                            let mut bindings = HashMap::new();
                            for dev in devices {
                                if let Some(ipv6) = dev.ipv6 {
                                    bindings.insert(dev.mac, ipv6);
                                }
                            }
                            bindings
                        }
                        Err(e) => {
                            tracing::error!("Failed to load DHCPv6 bindings: {e:?}");
                            HashMap::new()
                        }
                    }
                } else {
                    HashMap::new()
                };

                if let Some(mac) = iface.mac {
                    let link_ifindex = iface.index;
                    let lan_info = LanRouteInfo {
                        ifindex: iface.index,
                        iface_name: config.iface_name.clone(),
                        iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        mac: Some(mac.clone()),
                        prefix: 128,
                        mode: LanRouteMode::Reachable,
                    };
                    tokio::spawn(async move {
                        let IPV6RAConfig { ad_interval, ra_flag, source, dhcpv6 } = config.config;
                        let iface_name = config.iface_name;

                        // 1. Prefix setup
                        let PrefixSetupResult {
                            runtime,
                            ra_token,
                            dhcpv6_token,
                            change_notify,
                            cleanup_ips,
                        } = setup_prefix_sources(
                            source,
                            &iface_name,
                            &lan_info,
                            &route_service,
                            &prefix_map,
                        )
                        .await;

                        // 2. Spawn DHCPv6 server if configured
                        if let (Some(dhcpv6_config), Some(dhcpv6_assigned_info)) =
                            (dhcpv6, dhcpv6_assigned)
                        {
                            if dhcpv6_config.enable {
                                let pd_sources = runtime.pd_info.values().cloned().collect();
                                let static_infos = runtime.static_info.clone();
                                let dhcpv6_iface = iface_name.clone();
                                let dhcpv6_mac = mac.clone();
                                let dhcpv6_status = status_clone.clone();

                                let link_local = mac.to_ipv6_link_local();
                                tokio::spawn(async move {
                                    crate::dhcp_server::v6::dhcp_v6_server(
                                        link_ifindex,
                                        dhcpv6_iface,
                                        dhcpv6_mac,
                                        link_local,
                                        dhcpv6_config,
                                        pd_sources,
                                        static_infos,
                                        dhcpv6_status,
                                        dhcpv6_assigned_info,
                                        static_bindings,
                                    )
                                    .await;
                                    dhcpv6_token.cancel();
                                });
                            } else {
                                dhcpv6_token.cancel();
                            }
                        } else {
                            dhcpv6_token.cancel();
                        }

                        // 3. Run RA (blocks until exit)
                        let _ = crate::icmp::v6::icmp_ra_server(
                            ad_interval,
                            ra_flag,
                            mac,
                            iface_name.clone(),
                            status_clone,
                            &runtime,
                            change_notify,
                            assigned_ips,
                            true,
                            None,
                            None,
                            link_ifindex,
                        )
                        .await;

                        // 4. RA exits: cancel token so PD watch tasks detect
                        ra_token.cancel();

                        // 5. Cleanup
                        cleanup_prefix_sources(cleanup_ips, &iface_name, &route_service).await;
                    });
                }
            }
        }

        service_status
    }
}

#[derive(Clone)]
pub struct IPV6RAManagerService {
    store: IPV6RAServiceRepository,
    service: ServiceManager<IPV6RAService>,
    server_starter: IPV6RAService,
}

impl ControllerService for IPV6RAManagerService {
    type Id = String;
    type Config = IPV6RAServiceConfig;
    type DatabseAction = IPV6RAServiceRepository;
    type H = IPV6RAService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl IPV6RAManagerService {
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: broadcast::Receiver<IfaceObserverAction>,
        route_service: IpRouteService,
        prefix_map: IAPrefixMap,
    ) -> Self {
        let store = store_service.ra_service_store();
        let enrolled_device_store = store_service.enrolled_device_store();
        let server_starter = IPV6RAService::new(route_service, prefix_map, enrolled_device_store);
        let service =
            ServiceManager::init(store.list().await.unwrap(), server_starter.clone()).await;

        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(msg) = dev_observer.recv().await {
                match msg {
                    IfaceObserverAction::Up(iface_name) => {
                        tracing::info!("restart {iface_name} IPv6PD service");
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

        let store = store_service.ra_service_store();
        Self { service, store, server_starter }
    }

    pub async fn get_assigned_ips_by_iface_name(&self, iface_name: String) -> Option<IPv6NAInfo> {
        let info = {
            let read_lock = self.server_starter.iface_lease_map.read().await;
            read_lock.get(&iface_name).map(Clone::clone)
        };

        let Some(offer_info) = info else { return None };

        let data = offer_info.read().await.clone();
        return Some(data);
    }

    pub async fn get_assigned_ips(&self) -> HashMap<String, IPv6NAInfo> {
        let mut result = HashMap::new();

        let map = {
            let read_lock = self.server_starter.iface_lease_map.read().await;
            read_lock.clone()
        };

        for (iface_name, assigned_ips) in map {
            if let Ok(read) = assigned_ips.try_read() {
                result.insert(iface_name, read.clone());
            }
        }

        result
    }

    pub async fn get_dhcpv6_assigned_by_iface_name(
        &self,
        iface_name: String,
    ) -> Option<DHCPv6OfferInfo> {
        let info = {
            let read_lock = self.server_starter.iface_dhcpv6_map.read().await;
            read_lock.get(&iface_name).map(Clone::clone)
        };

        let Some(offer_info) = info else {
            return None;
        };

        let data = offer_info.read().await.clone();
        Some(data)
    }

    pub async fn get_dhcpv6_assigned(&self) -> HashMap<String, DHCPv6OfferInfo> {
        let mut result = HashMap::new();

        let map = {
            let read_lock = self.server_starter.iface_dhcpv6_map.read().await;
            read_lock.clone()
        };

        for (iface_name, assigned_info) in map {
            if let Ok(read) = assigned_info.try_read() {
                result.insert(iface_name, read.clone());
            }
        }

        result
    }
}
