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
};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::pppd::PPPDConfig;
use landscape_common::wan_service::pppoe::PppoeDataplane;

use crate::sys_service::route::IpRouteService;

/// The v4 acquisition section of a WAN link. Dispatches on the link kind:
/// ethernet → static / dhcp client on the attach iface, pppd → supervised
/// pppd session (address via IPCP), pppoe_native → eBPF PPPoE client
/// (address via IPCP).
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
    if !runtime.v4.enable {
        // Legacy semantics: `enable` gated the whole acquisition; the link
        // itself stays alive for its other sections.
        run_idle_until_stopped(iface, service_status, session).await;
        return;
    }

    match (runtime.kind, runtime.v4.model) {
        (RuntimeWanLinkKind::Ethernet, model) => match model {
            WanLinkV4Model::Nothing | WanLinkV4Model::Ipcp { .. } => {
                run_idle_until_stopped(iface, service_status, session).await;
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
        },
        (RuntimeWanLinkKind::Pppd { ppp_iface_name, peer_id, password, ac, plugin }, model) => {
            match model {
                WanLinkV4Model::Ipcp { default_router } => {
                    let pppd_config = PPPDConfig {
                        default_route: default_router,
                        peer_id,
                        password,
                        ac,
                        plugin,
                    };
                    crate::wan_service::pppd_service::run_pppd_for_link(
                        runtime.attach_iface_name,
                        ppp_iface_name,
                        pppd_config,
                        service_status,
                        route_service,
                        addr_binding,
                        session,
                    )
                    .await;
                }
                other => {
                    tracing::warn!(?other, "pppd link only supports the ipcp v4 model");
                    run_idle_until_stopped(iface, service_status, session).await;
                }
            }
        }
        (
            RuntimeWanLinkKind::PppoeNative {
                username,
                password,
                requested_mru,
                ac_name,
                lcp_echo_interval,
                redial_backoff_base_secs,
            },
            model,
        ) => match model {
            WanLinkV4Model::Ipcp { default_router } => {
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
            other => {
                tracing::warn!(?other, "pppoe_native link only supports the ipcp v4 model");
                run_idle_until_stopped(iface, service_status, session).await;
            }
        },
    }
}

/// 无 IP 模型时的占位运行:物理接口即会话接口,保持 `Running` 直到收到停止信号。
async fn run_idle_until_stopped(
    iface: LandscapeInterface,
    service_status: ServiceHandle,
    session: Option<LinkStateHandle>,
) {
    if let Some(session) = session.as_ref() {
        session.session_up(SessionIface::new(iface.index, iface.name.clone(), iface.mac));
    }
    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;
    if let Some(session) = session.as_ref() {
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
        run_idle_until_stopped(iface, service_status, session).await;
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
            SessionIface::new(iface.index, iface_name.clone(), iface.mac)
                .with_ip(Some(IpAddr::V4(ipv4))),
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
