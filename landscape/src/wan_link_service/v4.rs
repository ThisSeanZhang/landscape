use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT;
use landscape_common::args::LAND_HOSTNAME;
use landscape_common::dev::LandscapeInterface;
use landscape_common::global_const::default_router::{LD_ALL_ROUTERS, RouteInfo, RouteType};
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::sys_service::route_service::{LanRouteInfo, LanRouteMode, RouteTargetInfo};
use landscape_common::wan_link::{
    LinkStateHandle, RuntimeWanLinkConfig, RuntimeWanLinkKind, SessionIface, WanLinkV4Model,
    WanV4Lease,
};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::pppd::PPPDConfig;
use landscape_common::wan_service::pppoe::PppoeDataplane;

use crate::sys_service::route::IpRouteService;

/// v4 acquisition section. A PPP session is established while the link is
/// active (v4 or PD enabled); the default route is taken only when v4 is
/// enabled. Ethernet without acquisition intent publishes a lease-less anchor
/// only when PD needs one.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    iface: LandscapeInterface,
    runtime: RuntimeWanLinkConfig,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
    session: Option<LinkStateHandle>,
) {
    let attach_iface_name = runtime.attach_iface_name.clone();
    let v4_enable = runtime.v4.enable;
    let v4_model = runtime.v4.model.clone();
    let pd_enable = runtime.pd.enable;

    match runtime.kind {
        RuntimeWanLinkKind::Ethernet => {
            if !v4_enable {
                // No v4 acquisition: anchor the net iface for PD if needed.
                run_idle_until_stopped(iface, service_status, session, pd_enable).await;
                return;
            }
            match v4_model {
                WanLinkV4Model::Nothing | WanLinkV4Model::Ipcp { .. } => {
                    run_idle_until_stopped(iface, service_status, session, pd_enable).await;
                }
                WanLinkV4Model::Static {
                    ipv4,
                    ipv4_mask,
                    ipv6: _,
                    default_router,
                    default_router_ip,
                } => {
                    run_static_v4(
                        iface,
                        ipv4,
                        ipv4_mask,
                        default_router,
                        default_router_ip,
                        service_status,
                        route_service,
                        addr_binding,
                        session,
                    )
                    .await;
                }
                WanLinkV4Model::DhcpClient { hostname, default_router, custome_opts: _ } => {
                    run_dhcp_v4(
                        iface,
                        hostname,
                        default_router,
                        service_status,
                        route_service,
                        addr_binding,
                        session,
                    )
                    .await;
                }
            }
        }
        RuntimeWanLinkKind::Pppd { ppp_iface_name, peer_id, password, ac, plugin } => {
            let default_router =
                v4_enable && matches!(v4_model, WanLinkV4Model::Ipcp { default_router: true });
            let pppd_config = PPPDConfig {
                default_route: default_router,
                peer_id,
                password,
                ac,
                plugin,
            };
            crate::wan_service::pppd_service::run_pppd_for_link(
                attach_iface_name,
                ppp_iface_name,
                pppd_config,
                service_status,
                route_service,
                addr_binding,
                session,
            )
            .await;
        }
        RuntimeWanLinkKind::PppoeNative {
            username,
            password,
            requested_mru,
            ac_name,
            lcp_echo_interval,
            redial_backoff_base_secs,
        } => {
            let default_router =
                v4_enable && matches!(v4_model, WanLinkV4Model::Ipcp { default_router: true });
            run_pppoe_native(
                iface,
                username,
                password,
                requested_mru,
                ac_name,
                lcp_echo_interval,
                redial_backoff_base_secs,
                default_router,
                service_status,
                route_service,
                pppoe_dataplane,
                session,
            )
            .await;
        }
    }
}

/// Idle run: the net iface is the session anchor. `publish_session` publishes a
/// lease-less anchor (for PD); otherwise the session stays down and no section
/// starts.
async fn run_idle_until_stopped(
    iface: LandscapeInterface,
    service_status: ServiceHandle,
    session: Option<LinkStateHandle>,
    publish_session: bool,
) {
    if publish_session && let Some(session) = session.as_ref() {
        session.session_up(SessionIface::new(iface.index, iface.name.clone(), iface.mac), None);
    }
    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;
    if publish_session && let Some(session) = session.as_ref() {
        session.session_down();
    }
    service_status.just_change_status(ServiceStatus::Stop);
}

#[allow(clippy::too_many_arguments)]
async fn run_static_v4(
    iface: LandscapeInterface,
    ipv4: Option<Ipv4Addr>,
    ipv4_mask: Option<u8>,
    default_router: bool,
    default_router_ip: Option<Ipv4Addr>,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    session: Option<LinkStateHandle>,
) {
    // TODO: IPV6 的设置
    let (Some(ipv4), Some(ipv4_mask)) = (ipv4, ipv4_mask) else {
        tracing::warn!("static v4 model without ipv4/ipv4_mask, running idle");
        run_idle_until_stopped(iface, service_status, session, false).await;
        return;
    };

    let iface_name = iface.name.clone();
    tracing::info!("set ipv4 is: {}", ipv4);
    let _ = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{}/{}", ipv4, ipv4_mask), "dev", &iface_name])
        .output();
    addr_binding.bind_ipv4(iface.index, ipv4, default_router_ip, ipv4_mask, iface.mac);

    let lan_info = LanRouteInfo {
        ifindex: iface.index,
        iface_name: iface_name.clone(),
        iface_ip: IpAddr::V4(ipv4),
        mac: iface.mac,
        prefix: ipv4_mask,
        mode: LanRouteMode::WanReachable,
    };
    route_service.insert_ipv4_lan_route(&iface_name, lan_info).await;

    if let Some(default_router_ip) = default_router_ip
        && !default_router_ip.is_broadcast()
        && !default_router_ip.is_unspecified()
        && !default_router_ip.is_loopback()
    {
        if default_router {
            tracing::info!("setting default route: {:?}", default_router_ip);
            LD_ALL_ROUTERS
                .add_route(RouteInfo {
                    iface_name: iface_name.clone(),
                    weight: 1,
                    route: RouteType::Ipv4(default_router_ip),
                })
                .await;
        } else {
            LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
        }

        let info = RouteTargetInfo {
            ifindex: iface.index,
            weight: 1,
            mac: iface.mac,
            is_docker: false,
            iface_name: iface_name.clone(),
            iface_ip: IpAddr::V4(ipv4),
            default_route: default_router,
            gateway_ip: IpAddr::V4(default_router_ip),
        };
        route_service.insert_ipv4_wan_route(&iface_name, info).await;
    }

    if let Some(session) = session.as_ref() {
        session.session_up(
            SessionIface::new(iface.index, iface_name.clone(), iface.mac),
            Some(WanV4Lease::new(iface.index, ipv4)),
        );
    }

    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    if let Some(session) = session.as_ref() {
        session.session_down();
    }

    let _ = std::process::Command::new("ip")
        .args(["addr", "del", &format!("{}/{}", ipv4, ipv4_mask), "dev", &iface_name])
        .output();

    if default_router {
        LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
    }
    route_service.remove_ipv4_wan_route(&iface_name).await;
    route_service.remove_ipv4_lan_route(&iface_name).await;
    addr_binding.unbind_ipv4(iface.index);
    service_status.just_change_status(ServiceStatus::Stop);
}

#[allow(clippy::too_many_arguments)]
async fn run_dhcp_v4(
    iface: LandscapeInterface,
    hostname: Option<String>,
    default_router: bool,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    session: Option<LinkStateHandle>,
) {
    if let Some(mac_addr) = iface.mac {
        let hostname = hostname.filter(|h| !h.is_empty()).unwrap_or_else(|| LAND_HOSTNAME.clone());
        crate::wan_service::dhcpv4_client::v4::dhcp_v4_client(
            iface.index,
            iface.name,
            mac_addr,
            LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
            service_status,
            hostname,
            default_router,
            route_service,
            addr_binding,
            session,
        )
        .await;
    } else {
        service_status.just_change_status(ServiceStatus::Failed);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_pppoe_native(
    iface: LandscapeInterface,
    username: String,
    password: String,
    requested_mru: u16,
    ac_name: Option<String>,
    lcp_echo_interval: Option<u32>,
    redial_backoff_base_secs: Option<u64>,
    default_router: bool,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
    session: Option<LinkStateHandle>,
) {
    if let Some(mac_addr) = iface.mac {
        let mut config = crate::wan_service::pppoe_client::PPPoEClientConfig::new(
            iface.index,
            iface.name,
            mac_addr,
            username,
            password,
            default_router,
            requested_mru,
            ac_name,
        );
        config.lcp_echo_interval = lcp_echo_interval.map(u64::from);
        config.redial_backoff_base_secs = redial_backoff_base_secs;
        crate::wan_service::pppoe_client::run(
            config,
            service_status,
            route_service,
            pppoe_dataplane,
            session,
        )
        .await;
    } else {
        service_status.just_change_status(ServiceStatus::Failed);
    }
}
