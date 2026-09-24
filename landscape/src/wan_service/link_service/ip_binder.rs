use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use landscape_common::dev::LandscapeInterface;
use landscape_common::global_const::default_router::{RouteInfo, RouteType, LD_ALL_ROUTERS};
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::sys_service::route_service::{LanRouteInfo, LanRouteMode, RouteTargetInfo};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::link::session::{SessionSignal, SessionState, WanV4Lease};
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

use super::drivers::StaticSpec;

/// Seam over host-mutating shell-outs (`ip addr`) so the static binding path
/// is unit-testable. Implementations must be idempotent-tolerant: legacy
/// semantics ignore failures (best effort `let _ =`).
#[async_trait::async_trait]
pub trait SystemIfaceOps: Send + Sync {
    async fn add_addr(&self, iface: &str, cidr: &str);
    async fn del_addr(&self, iface: &str, cidr: &str);
    async fn add_ipv6(&self, iface: &str, ip: Ipv6Addr);
    async fn del_ipv6(&self, iface: &str, ip: Ipv6Addr);
}

/// Production impl: shells out to `ip`, exactly like the legacy static arm.
pub struct ShellSystemIfaceOps;

impl ShellSystemIfaceOps {
    fn run(args: &[&str]) {
        let _ = std::process::Command::new("ip").args(args).output();
    }
}

#[async_trait::async_trait]
impl SystemIfaceOps for ShellSystemIfaceOps {
    async fn add_addr(&self, iface: &str, cidr: &str) {
        Self::run(&["addr", "add", cidr, "dev", iface]);
    }

    async fn del_addr(&self, iface: &str, cidr: &str) {
        Self::run(&["addr", "del", cidr, "dev", iface]);
    }

    async fn add_ipv6(&self, iface: &str, ip: Ipv6Addr) {
        let cidr = format!("{ip}/64");
        Self::run(&["-6", "addr", "add", &cidr, "dev", iface]);
    }

    async fn del_ipv6(&self, iface: &str, ip: Ipv6Addr) {
        let cidr = format!("{ip}/64");
        Self::run(&["-6", "addr", "del", &cidr, "dev", iface]);
    }
}

/// Seam over the global kernel default-route table (`LD_ALL_ROUTERS`).
#[async_trait::async_trait]
pub trait DefaultRouteOps: Send + Sync {
    async fn add(&self, info: RouteInfo);
    async fn del_by_iface(&self, iface: &str);
}

pub struct LdDefaultRouteOps;

#[async_trait::async_trait]
impl DefaultRouteOps for LdDefaultRouteOps {
    async fn add(&self, info: RouteInfo) {
        LD_ALL_ROUTERS.add_route(info).await;
    }

    async fn del_by_iface(&self, iface: &str) {
        LD_ALL_ROUTERS.del_route_by_iface(iface).await;
    }
}

fn usable_gateway(gw: &Ipv4Addr) -> bool {
    !gw.is_broadcast() && !gw.is_unspecified() && !gw.is_loopback()
}

/// The legacy static binding sequence, extracted from the former
/// `ipconfig_service` static arm: assign the address, bind it into the eBPF
/// wan-ip map, register lan/wan routes and (optionally) the kernel default
/// route; on stop tear everything down in reverse. The WAN route owner is the
/// link uuid.
#[allow(clippy::too_many_arguments)]
pub async fn run_static_v4(
    link_id: Uuid,
    link_chain_id: u16,
    iface: LandscapeInterface,
    spec: StaticSpec,
    status: WatchService,
    session: SessionSignal,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    system_ops: Arc<dyn SystemIfaceOps>,
    default_routes: Arc<dyn DefaultRouteOps>,
) {
    status.just_change_status(ServiceStatus::Staring);
    session.set(SessionState::Starting);

    let iface_name = iface.name.clone();
    let cidr = format!("{}/{}", spec.ipv4, spec.mask);
    tracing::info!(iface = %iface_name, "static v4 binding: {cidr}");
    system_ops.add_addr(&iface_name, &cidr).await;
    if let Some(ipv6) = spec.ipv6 {
        system_ops.add_ipv6(&iface_name, ipv6).await;
    }

    addr_binding.bind_ipv4(
        iface.index,
        link_chain_id,
        spec.ipv4,
        spec.default_router_ip,
        spec.mask,
        iface.mac,
    );

    route_service
        .insert_ipv4_lan_route(
            &iface_name,
            LanRouteInfo {
                ifindex: iface.index,
                iface_name: iface_name.clone(),
                iface_ip: IpAddr::V4(spec.ipv4),
                mac: iface.mac,
                prefix: spec.mask,
                mode: LanRouteMode::WanReachable,
            },
        )
        .await;

    let mut default_route_registered = false;
    let mut gateway = None;
    if let Some(gw) = spec.default_router_ip.filter(usable_gateway) {
        gateway = Some(gw);
        if spec.default_router {
            tracing::info!(iface = %iface_name, "setting default route: {gw}");
            default_routes
                .add(RouteInfo {
                    iface_name: iface_name.clone(),
                    weight: 1,
                    route: RouteType::Ipv4(gw),
                })
                .await;
            default_route_registered = true;
        } else {
            default_routes.del_by_iface(&iface_name).await;
        }

        route_service
            .insert_ipv4_link_route(
                link_id,
                RouteTargetInfo {
                    ifindex: iface.index,
                    link_chain_id,
                    weight: 1,
                    mac: iface.mac,
                    is_docker: false,
                    iface_name: iface_name.clone(),
                    iface_ip: IpAddr::V4(spec.ipv4),
                    default_route: spec.default_router,
                    gateway_ip: IpAddr::V4(gw),
                },
            )
            .await;
    }

    status.just_change_status(ServiceStatus::Running);
    session.set(SessionState::Ready {
        lease: Some(WanV4Lease {
            ifindex: iface.index,
            ip: spec.ipv4,
            gateway: gateway.unwrap_or(spec.ipv4),
        }),
    });
    status.wait_to_stopping().await;

    // Teardown mirrors setup in reverse.
    system_ops.del_addr(&iface_name, &cidr).await;
    if let Some(ipv6) = spec.ipv6 {
        system_ops.del_ipv6(&iface_name, ipv6).await;
    }
    if default_route_registered {
        default_routes.del_by_iface(&iface_name).await;
    }
    route_service.remove_ipv4_link_route(link_id).await;
    route_service.remove_ipv4_lan_route(&iface_name).await;
    addr_binding.unbind_ipv4(iface.index, link_chain_id);
    session.set(SessionState::Idle);
    status.just_change_status(ServiceStatus::Stop);
}
