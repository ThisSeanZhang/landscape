use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::global_const::default_router::LD_ALL_ROUTERS;
use landscape_common::global_const::default_router::RouteInfo;
use landscape_common::global_const::default_router::RouteType;
use landscape_common::sys_service::route_service::LanRouteInfo;
use landscape_common::sys_service::route_service::LanRouteMode;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use landscape_common::wan_service::addr_binding::WanAddrBinding;

use crate::sys_service::route::IpRouteService;

use uuid::Uuid;

const PPPD_RETRY_BASE_SECS: u64 = 4;
const PPPD_RETRY_MAX_SECS: u64 = 10 * 60;
const PPPD_STARTUP_TIMEOUT_SECS: u64 = 90;
const PPPD_STOP_GRACE_SECS: u64 = 5;
const PPPD_STOP_KILL_WAIT_SECS: u64 = 2;
const PPPD_POLL_INTERVAL_MS: u64 = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PppIpv4State {
    Missing,
    Partial { ifindex: u32, local: Option<Ipv4Addr>, peer: Option<Ipv4Addr> },
    Ready { ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr },
}

impl PppIpv4State {
    pub(crate) fn from_snapshot(
        ip4addr: Option<(u32, Option<Ipv4Addr>, Option<Ipv4Addr>)>,
    ) -> Self {
        match ip4addr {
            Some((ifindex, Some(local), Some(peer))) => Self::Ready { ifindex, local, peer },
            Some((ifindex, local, peer)) => Self::Partial { ifindex, local, peer },
            None => Self::Missing,
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PppdTimings {
    pub retry_base: Duration,
    pub retry_max: Duration,
    pub startup_timeout: Duration,
    pub stop_grace: Duration,
    pub stop_kill_wait: Duration,
    pub poll_interval: Duration,
}

impl Default for PppdTimings {
    fn default() -> Self {
        Self {
            retry_base: Duration::from_secs(PPPD_RETRY_BASE_SECS),
            retry_max: Duration::from_secs(PPPD_RETRY_MAX_SECS),
            startup_timeout: Duration::from_secs(PPPD_STARTUP_TIMEOUT_SECS),
            stop_grace: Duration::from_secs(PPPD_STOP_GRACE_SECS),
            stop_kill_wait: Duration::from_secs(PPPD_STOP_KILL_WAIT_SECS),
            poll_interval: Duration::from_millis(PPPD_POLL_INTERVAL_MS),
        }
    }
}

impl PppdTimings {
    pub(crate) fn backoff(&self, failure_count: u32) -> Duration {
        let exp = failure_count.saturating_sub(1).min(31);
        let multiplier = 1u32 << exp;
        self.retry_base.saturating_mul(multiplier).min(self.retry_max)
    }
}

#[async_trait::async_trait]
pub(crate) trait PppdChild: Send {
    async fn wait(&mut self) -> io::Result<ExitStatus>;
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
    async fn signal_group(&self, signal: i32) -> io::Result<()>;
}

#[async_trait::async_trait]
pub(crate) trait PppdEnv: Send + Sync {
    async fn spawn(&self, iface: &str) -> io::Result<Box<dyn PppdChild>>;
    async fn poll_addr(&self, iface: &str) -> PppIpv4State;
    async fn on_addr_ready(&self, state: &PppIpv4State, as_router: bool, iface: &str);
    async fn cleanup(&self, iface: &str, as_router: bool);
}

/// Side-effect boundary for IPv4 binding and route/default-route management.
///
/// Abstracted so [`SystemPppdEnv`]'s decision logic can be tested without
/// touching the real `IpRouteService`, `WanAddrBinding`, or the process-global
/// `LD_ALL_ROUTERS` (which shells out to `ip route`).
#[async_trait::async_trait]
pub(crate) trait PppRouteSink: Send + Sync {
    fn bind_ipv4(&self, ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr, mask: u8);
    async fn insert_wan_route(&self, iface: &str, info: RouteTargetInfo);
    async fn insert_lan_route(&self, iface: &str, info: LanRouteInfo);
    async fn add_default_route(&self, iface: &str);
    async fn del_default_route(&self, iface: &str);
    async fn remove_wan_route(&self, iface: &str);
    async fn remove_lan_route(&self, iface: &str);
}

pub(crate) struct SystemRouteSink {
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    link_id: Uuid,
}

impl SystemRouteSink {
    pub(crate) fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        link_id: Uuid,
    ) -> Self {
        Self { route_service, addr_binding, link_id }
    }
}

#[async_trait::async_trait]
impl PppRouteSink for SystemRouteSink {
    fn bind_ipv4(&self, ifindex: u32, local: Ipv4Addr, peer: Ipv4Addr, mask: u8) {
        self.addr_binding.bind_ipv4(ifindex, local, Some(peer), mask, None);
    }

    async fn insert_wan_route(&self, _iface: &str, info: RouteTargetInfo) {
        self.route_service.insert_ipv4_link_route(self.link_id, info).await;
    }

    async fn insert_lan_route(&self, iface: &str, info: LanRouteInfo) {
        self.route_service.insert_ipv4_lan_route(iface, info).await;
    }

    async fn add_default_route(&self, iface: &str) {
        LD_ALL_ROUTERS
            .add_route(RouteInfo {
                iface_name: iface.to_string(),
                weight: 1,
                route: RouteType::PPP,
            })
            .await;
    }

    async fn del_default_route(&self, iface: &str) {
        LD_ALL_ROUTERS.del_route_by_iface(iface).await;
    }

    async fn remove_wan_route(&self, _iface: &str) {
        self.route_service.remove_ipv4_link_route(self.link_id).await;
    }

    async fn remove_lan_route(&self, iface: &str) {
        self.route_service.remove_ipv4_lan_route(iface).await;
    }
}

pub(crate) struct SystemPppdEnv {
    sink: Arc<dyn PppRouteSink>,
}

impl SystemPppdEnv {
    pub(crate) fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        link_id: Uuid,
    ) -> Self {
        Self {
            sink: Arc::new(SystemRouteSink::new(route_service, addr_binding, link_id)),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_sink(sink: Arc<dyn PppRouteSink>) -> Self {
        Self { sink }
    }
}

struct TokioPppChild {
    child: tokio::process::Child,
    pgid: Option<i32>,
}

#[async_trait::async_trait]
impl PppdChild for TokioPppChild {
    async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait().await
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    async fn signal_group(&self, signal: i32) -> io::Result<()> {
        let Some(pgid) = self.pgid else {
            return Ok(());
        };

        let result = unsafe { libc::killpg(pgid, signal) };
        if result == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) { Ok(()) } else { Err(err) }
    }
}

#[async_trait::async_trait]
impl PppdEnv for SystemPppdEnv {
    async fn spawn(&self, iface: &str) -> io::Result<Box<dyn PppdChild>> {
        let mut command = tokio::process::Command::new("pppd");
        command
            .arg("nodetach")
            .arg("call")
            .arg(iface)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .process_group(0)
            .kill_on_drop(true);

        let child = command.spawn()?;
        let pgid = child.id().and_then(|id| i32::try_from(id).ok());
        Ok(Box::new(TokioPppChild { child, pgid }))
    }

    async fn poll_addr(&self, iface: &str) -> PppIpv4State {
        PppIpv4State::from_snapshot(crate::get_ppp_address(iface).await)
    }

    async fn on_addr_ready(&self, state: &PppIpv4State, as_router: bool, iface: &str) {
        let PppIpv4State::Ready { ifindex, local, peer } = state else {
            return;
        };

        self.sink.bind_ipv4(*ifindex, *local, *peer, 32);

        self.sink
            .insert_wan_route(
                iface,
                RouteTargetInfo {
                    ifindex: *ifindex,
                    weight: 1,
                    mac: None,
                    is_docker: false,
                    iface_name: iface.to_string(),
                    iface_ip: IpAddr::V4(*local),
                    default_route: as_router,
                    gateway_ip: IpAddr::V4(*peer),
                },
            )
            .await;

        self.sink
            .insert_lan_route(
                iface,
                LanRouteInfo {
                    ifindex: *ifindex,
                    iface_name: iface.to_string(),
                    iface_ip: IpAddr::V4(*local),
                    mac: None,
                    prefix: 32,
                    mode: LanRouteMode::WanReachable,
                },
            )
            .await;

        if as_router {
            self.sink.add_default_route(iface).await;
        } else {
            self.sink.del_default_route(iface).await;
        }
    }

    async fn cleanup(&self, iface: &str, as_router: bool) {
        if as_router {
            self.sink.del_default_route(iface).await;
        }
        self.sink.remove_wan_route(iface).await;
        self.sink.remove_lan_route(iface).await;
    }
}
