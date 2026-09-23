use std::sync::Arc;

use landscape_common::concurrency::{spawn_task_with_resource, task_label};
use landscape_common::dev::LandscapeInterface;
use landscape_common::event::hub::IAPrefixEventSender;
use landscape_common::net::MacAddr;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;
use landscape_common::wan_service::link::session::{SessionSignal, SessionState};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::wan_service::pppd::PPPDConfig;
use landscape_common::wan_service::pppoe::PppoeDataplane;
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT;
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;
use crate::wan_service::pppoe_client::PPPoEClientConfig;

use super::ip_binder::{run_static_v4, DefaultRouteOps, SystemIfaceOps};

/// Resolves kernel interfaces by name. The production impl wraps netlink;
/// tests substitute a synthetic table.
#[async_trait::async_trait]
pub trait IfaceLookup: Send + Sync {
    async fn get(&self, name: &str) -> Option<LandscapeInterface>;
}

pub struct NetlinkIfaceLookup;

#[async_trait::async_trait]
impl IfaceLookup for NetlinkIfaceLookup {
    async fn get(&self, name: &str) -> Option<LandscapeInterface> {
        crate::get_iface_by_name(name).await
    }
}

/// Fully-resolved session/v4 acquisition work for one link start.
#[derive(Clone, Debug)]
pub enum SessionSpec {
    /// No session child (ethernet without v4 intent, or static configured
    /// without an address — legacy "assign nothing" semantics).
    None,
    Static(StaticSpec),
    Dhcp {
        hostname: Option<String>,
        default_router: bool,
    },
    PppoeNative(Box<PPPoEClientConfig>),
    Pppd {
        attach_iface_name: String,
        ppp_iface_name: String,
        config: PPPDConfig,
    },
}

#[derive(Clone, Debug)]
pub struct StaticSpec {
    pub ipv4: std::net::Ipv4Addr,
    pub mask: u8,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub default_router: bool,
    pub default_router_ip: Option<std::net::Ipv4Addr>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PdSpec {
    pub mac: MacAddr,
    pub expected_pd_len: u8,
}

/// One link sub-service attachment on the net iface.
#[derive(Clone, Debug)]
pub enum SectionTask {
    Pd(PdSpec),
    Nat(NatConfig),
    Firewall,
    Mss { clamp_size: u16 },
}

/// Executes the session/v4 acquisition. The production impl reuses the
/// legacy drivers verbatim; tests substitute a mock.
#[async_trait::async_trait]
pub trait SessionDriver: Send + Sync {
    /// Spawns the driver; the driver owns `status` and publishes transitions
    /// on `session` until it reaches a terminal state.
    async fn spawn(
        &self,
        link_id: Uuid,
        iface: LandscapeInterface,
        spec: SessionSpec,
        status: WatchService,
        session: SessionSignal,
    );
}

#[derive(Clone)]
pub struct RealSessionDriver {
    pub route_service: IpRouteService,
    pub addr_binding: Arc<dyn WanAddrBinding>,
    pub pppoe_dataplane: Arc<dyn PppoeDataplane>,
    pub system_ops: Arc<dyn SystemIfaceOps>,
    pub default_routes: Arc<dyn DefaultRouteOps>,
}

#[async_trait::async_trait]
impl SessionDriver for RealSessionDriver {
    async fn spawn(
        &self,
        link_id: Uuid,
        iface: LandscapeInterface,
        spec: SessionSpec,
        status: WatchService,
        session: SessionSignal,
    ) {
        let route_service = self.route_service.clone();
        let addr_binding = self.addr_binding.clone();
        let pppoe_dataplane = self.pppoe_dataplane.clone();
        let system_ops = self.system_ops.clone();
        let default_routes = self.default_routes.clone();
        let _handle = spawn_task_with_resource(
            task_label::task::WAN_LINK_SESSION,
            link_id.to_string(),
            async move {
                match spec {
                    SessionSpec::None => {
                        // No v4 acquisition: the anchor is the net iface being
                        // present. Publish Ready immediately.
                        status.just_change_status(ServiceStatus::Running);
                        session.set(SessionState::Ready { lease: None });
                        status.wait_to_stopping().await;
                        session.set(SessionState::Idle);
                        status.just_change_status(ServiceStatus::Stop);
                    }
                    SessionSpec::Static(static_spec) => {
                        run_static_v4(
                            link_id,
                            iface,
                            static_spec,
                            status,
                            session,
                            route_service,
                            addr_binding,
                            system_ops,
                            default_routes,
                        )
                        .await;
                    }
                    SessionSpec::Dhcp { hostname, default_router } => {
                        if let Some(mac) = iface.mac {
                            let hostname = hostname
                                .filter(|h| !h.is_empty())
                                .unwrap_or_else(|| landscape_common::args::LAND_HOSTNAME.clone());
                            crate::wan_service::dhcpv4_client::v4::dhcp_v4_client(
                                iface.index,
                                iface.name,
                                mac,
                                landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
                                status,
                                hostname,
                                default_router,
                                route_service,
                                addr_binding,
                                link_id,
                                session,
                            )
                            .await;
                        } else {
                            status.just_change_status(ServiceStatus::Failed);
                            session.set(SessionState::Failed);
                        }
                    }
                    SessionSpec::PppoeNative(config) => {
                        crate::wan_service::pppoe_client::run(
                            *config,
                            status,
                            route_service,
                            pppoe_dataplane,
                            session,
                        )
                        .await;
                    }
                    SessionSpec::Pppd { attach_iface_name, ppp_iface_name, config } => {
                        crate::wan_service::pppd_service::spawn_pppd_session(
                            attach_iface_name,
                            ppp_iface_name,
                            config,
                            status,
                            route_service,
                            addr_binding,
                            link_id,
                            session,
                        )
                        .await;
                    }
                }
            },
        );
    }
}

/// Dependencies the section runner needs for PD.
#[derive(Clone)]
pub struct PdDeps {
    pub route_service: IpRouteService,
    pub addr_binding: Arc<dyn WanAddrBinding>,
    pub prefix_map: IAPrefixMap,
    pub shared_wan_iid: Arc<u64>,
    pub prefix_sender: IAPrefixEventSender,
}

/// Spawns link sub-services (pd / nat / firewall / mss) on the net iface,
/// reusing the legacy service bodies.
#[async_trait::async_trait]
pub trait SectionRunner: Send + Sync {
    async fn spawn(
        &self,
        link_id: Uuid,
        iface: LandscapeInterface,
        task: SectionTask,
        status: WatchService,
    );
}

#[derive(Clone)]
pub struct RealSectionRunner {
    pub nat: Arc<dyn NatDataplane>,
    pub firewall: Arc<dyn FirewallDataplane>,
    pub mss: Arc<dyn MssClampDataplane>,
    pub pd: PdDeps,
}

#[async_trait::async_trait]
impl SectionRunner for RealSectionRunner {
    async fn spawn(
        &self,
        link_id: Uuid,
        iface: LandscapeInterface,
        task: SectionTask,
        status: WatchService,
    ) {
        let iface_name = iface.name.clone();
        let ifindex = iface.index as i32;
        let has_mac = iface.mac.is_some();
        match task {
            SectionTask::Nat(nat_config) => {
                let dataplane = self.nat.clone();
                let _handle = spawn_task_with_resource(
                    task_label::task::WAN_LINK_SECTION,
                    format!("{iface_name}.nat"),
                    async move {
                        crate::wan_service::nat_service::create_nat_service(
                            iface_name, ifindex, has_mac, nat_config, status, dataplane,
                        )
                        .await;
                    },
                );
            }
            SectionTask::Firewall => {
                let dataplane = self.firewall.clone();
                let _handle = spawn_task_with_resource(
                    task_label::task::WAN_LINK_SECTION,
                    format!("{iface_name}.firewall"),
                    async move {
                        crate::wan_service::firewall::create_firewall_service(
                            iface_name, ifindex, has_mac, status, dataplane,
                        )
                        .await;
                    },
                );
            }
            SectionTask::Mss { clamp_size } => {
                let dataplane = self.mss.clone();
                let _handle = spawn_task_with_resource(
                    task_label::task::WAN_LINK_SECTION,
                    format!("{iface_name}.mss"),
                    async move {
                        crate::wan_service::mss_clamp_service::run_mss_clamp(
                            iface_name, ifindex, clamp_size, has_mac, status, dataplane,
                        )
                        .await;
                    },
                );
            }
            SectionTask::Pd(pd) => {
                let pd_deps = self.pd.clone();
                let _handle = spawn_task_with_resource(
                    task_label::task::WAN_LINK_SECTION,
                    format!("{iface_name}.pd"),
                    async move {
                        let route_info =
                            landscape_common::sys_service::route_service::RouteTargetInfo {
                                ifindex: iface.index,
                                weight: 1,
                                mac: iface.mac,
                                is_docker: false,
                                iface_name: iface_name.clone(),
                                iface_ip: std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                                default_route: true,
                                gateway_ip: std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            };
                        crate::wan_service::ipv6pd_client::v6::dhcp_v6_pd_client(
                            iface_name,
                            link_id,
                            iface.index,
                            iface.mac,
                            pd.mac,
                            pd.expected_pd_len,
                            LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
                            status,
                            route_info,
                            pd_deps.route_service,
                            pd_deps.addr_binding,
                            pd_deps.prefix_map,
                            pd_deps.shared_wan_iid,
                            pd_deps.prefix_sender,
                        )
                        .await;
                    },
                );
            }
        }
    }
}

#[cfg(test)]
pub mod mocks {
    use std::sync::Mutex;

    use landscape_common::wan_service::link::session::WanV4Lease;
    use tokio::sync::mpsc;

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum SessionBehavior {
        RunUntilStop,
        FailFast,
    }

    pub struct MockSessionDriver {
        pub calls: Arc<Mutex<Vec<(Uuid, String, SessionSpec)>>>,
        pub behavior: SessionBehavior,
        pub lease: Option<WanV4Lease>,
        /// Present for `controlled` drivers: the spawned task applies every
        /// state pushed through the paired [`MockSessionControl`].
        control: Mutex<Option<mpsc::UnboundedReceiver<SessionState>>>,
    }

    /// Lets a test drive an already-spawned session through arbitrary
    /// [`SessionState`] transitions (lease change, `Lost`, recovery, ...).
    pub struct MockSessionControl {
        state_tx: mpsc::UnboundedSender<SessionState>,
    }

    impl MockSessionControl {
        pub fn set(&self, state: SessionState) {
            let _ = self.state_tx.send(state);
        }

        pub fn go_lost(&self) {
            self.set(SessionState::Lost { retrying: true });
        }

        pub fn go_ready(&self, lease: Option<WanV4Lease>) {
            self.set(SessionState::Ready { lease });
        }
    }

    impl MockSessionDriver {
        pub fn new(behavior: SessionBehavior) -> Self {
            Self {
                calls: Arc::default(),
                behavior,
                lease: None,
                control: Mutex::new(None),
            }
        }

        pub fn with_lease(mut self, lease: WanV4Lease) -> Self {
            self.lease = Some(lease);
            self
        }

        /// A driver whose session state is scripted by the returned control
        /// handle. The initial state is `Ready { lease: Some(lease) }`.
        pub fn controlled(lease: WanV4Lease) -> (Arc<Self>, MockSessionControl) {
            let (state_tx, state_rx) = mpsc::unbounded_channel();
            let driver = Arc::new(Self {
                calls: Arc::default(),
                behavior: SessionBehavior::RunUntilStop,
                lease: Some(lease),
                control: Mutex::new(Some(state_rx)),
            });
            (driver, MockSessionControl { state_tx })
        }
    }

    #[async_trait::async_trait]
    impl SessionDriver for MockSessionDriver {
        async fn spawn(
            &self,
            link_id: Uuid,
            iface: LandscapeInterface,
            spec: SessionSpec,
            status: WatchService,
            session: SessionSignal,
        ) {
            self.calls.lock().unwrap().push((link_id, iface.name.clone(), spec));
            let behavior = self.behavior;
            let lease = self.lease;
            let control = self.control.lock().unwrap().take();
            let _handle = tokio::spawn(async move {
                status.just_change_status(ServiceStatus::Staring);
                match behavior {
                    SessionBehavior::RunUntilStop => {
                        status.just_change_status(ServiceStatus::Running);
                        session.set(SessionState::Ready { lease });
                        match control {
                            Some(mut rx) => {
                                let stopper = status.wait_to_stopping();
                                tokio::pin!(stopper);
                                loop {
                                    tokio::select! {
                                        _ = &mut stopper => break,
                                        maybe = rx.recv() => match maybe {
                                            Some(state) => session.set(state),
                                            None => break,
                                        },
                                    }
                                }
                            }
                            None => status.wait_to_stopping().await,
                        }
                        status.just_change_status(ServiceStatus::Stop);
                        session.set(SessionState::Idle);
                    }
                    SessionBehavior::FailFast => {
                        status.just_change_status(ServiceStatus::Failed);
                        session.set(SessionState::Failed);
                    }
                }
            });
        }
    }

    pub struct MockSectionRunner {
        pub calls: Arc<Mutex<Vec<(Uuid, String, SectionTask)>>>,
        /// Kinds that reached `Stop`, in completion order.
        pub stopped: Arc<Mutex<Vec<&'static str>>>,
        /// Section kind names ("pd" / "nat" / "firewall" / "mss") that fail
        /// instead of running.
        pub fail: Vec<&'static str>,
    }

    impl MockSectionRunner {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Arc::default(),
                stopped: Arc::default(),
                fail: Vec::new(),
            })
        }

        pub fn kind_name(task: &SectionTask) -> &'static str {
            match task {
                SectionTask::Pd(_) => "pd",
                SectionTask::Nat(_) => "nat",
                SectionTask::Firewall => "firewall",
                SectionTask::Mss { .. } => "mss",
            }
        }

        pub fn stop_count(&self, kind: &str) -> usize {
            self.stopped.lock().unwrap().iter().filter(|k| **k == kind).count()
        }
    }

    #[async_trait::async_trait]
    impl SectionRunner for MockSectionRunner {
        async fn spawn(
            &self,
            link_id: Uuid,
            iface: LandscapeInterface,
            task: SectionTask,
            status: WatchService,
        ) {
            self.calls.lock().unwrap().push((link_id, iface.name.clone(), task.clone()));
            let kind = Self::kind_name(&task);
            let fail = self.fail.contains(&kind);
            let stopped = self.stopped.clone();
            let _handle = tokio::spawn(async move {
                status.just_change_status(ServiceStatus::Staring);
                if fail {
                    status.just_change_status(ServiceStatus::Failed);
                    return;
                }
                status.just_change_status(ServiceStatus::Running);
                status.wait_to_stopping().await;
                status.just_change_status(ServiceStatus::Stop);
                stopped.lock().unwrap().push(kind);
            });
        }
    }

    /// Static iface table for tests.
    pub struct StaticIfaceLookup(pub Vec<LandscapeInterface>);

    #[async_trait::async_trait]
    impl IfaceLookup for StaticIfaceLookup {
        async fn get(&self, name: &str) -> Option<LandscapeInterface> {
            self.0.iter().find(|iface| iface.name == name).cloned()
        }
    }

    pub fn test_iface(
        name: &str,
        index: u32,
        mac: Option<landscape_common::net::MacAddr>,
    ) -> LandscapeInterface {
        use landscape_common::dev::{DevState, DeviceKind, DeviceType};
        LandscapeInterface {
            name: name.to_string(),
            index,
            mac,
            perm_mac: mac,
            dev_type: DeviceType::Ethernet,
            dev_kind: DeviceKind::UnKnow,
            dev_status: DevState::default(),
            controller_id: None,
            carrier: true,
            netns_id: None,
            peer_link_id: None,
            is_wireless: false,
        }
    }
}
