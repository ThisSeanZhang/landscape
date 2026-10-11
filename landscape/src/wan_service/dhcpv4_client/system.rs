use landscape_common::SYSCTL_IPV4_RP_FILTER_PATTERN;
use landscape_common::global_const::default_router::{LD_ALL_ROUTERS, RouteInfo, RouteType};
use landscape_common::net_proto::dhcp::{
    DhcpV4Option as DhcpOption, DhcpV4OptionCode as OptionCode,
};
use landscape_common::sys_service::route_service::{LanRouteInfo, LanRouteMode, RouteTargetInfo};
use std::net::{IpAddr, Ipv4Addr};

use super::fsm::LeaseParams;
use super::{DhcpV4ClientServiceRuntimeConfig, DhcpV4ClientServices};

pub(crate) struct AppliedAddr {
    pub(crate) ip: Ipv4Addr,
    pub(crate) prefix: u8,
}

pub(crate) fn disable_rp_filter(iface_name: &str) {
    use sysctl::Sysctl;
    if let Ok(ctl) = sysctl::Ctl::new(&SYSCTL_IPV4_RP_FILTER_PATTERN.replace("{}", iface_name)) {
        match ctl.set_value_string("0") {
            Ok(value) => {
                if value != "0" {
                    tracing::error!("modify value error: {:?}", value)
                }
            }
            Err(e) => {
                tracing::error!("err: {e:?}")
            }
        }
    }
}

async fn run_ip_cmd(args: &[String]) {
    match tokio::process::Command::new("ip").args(args).output().await {
        Ok(output) => {
            if !output.status.success() {
                tracing::error!(
                    "ip {:?} failed: {:?}",
                    args,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => tracing::error!("spawn ip command failed: {:?}", e),
    }
}

pub(crate) async fn apply_lease(
    params: &LeaseParams,
    config: &DhcpV4ClientServiceRuntimeConfig,
    services: &DhcpV4ClientServices,
    applied: &mut Option<AppliedAddr>,
) {
    if let Some(prev) = applied.take()
        && (prev.ip != params.yiaddr || prev.prefix != params.prefix as u8)
    {
        run_ip_cmd(&[
            "addr".to_string(),
            "del".to_string(),
            format!("{}/{}", prev.ip, prev.prefix),
            "dev".to_string(),
            config.iface_name.clone(),
        ])
        .await;
    }

    let mut args = vec![
        "addr".to_string(),
        "replace".to_string(),
        format!("{}/{}", params.yiaddr, params.prefix),
    ];

    if let Some(DhcpOption::BroadcastAddr(broadcast)) =
        params.options.get(OptionCode::BroadcastAddr)
    {
        args.extend(["brd".to_string(), format!("{}", broadcast)]);
    }
    args.extend([
        "dev".to_string(),
        config.iface_name.clone(),
        "valid_lft".to_string(),
        format!("{}", params.lease_time),
        "preferred_lft".to_string(),
        format!("{}", params.renew_time),
    ]);

    tracing::info!("{:?}", args);
    run_ip_cmd(&args).await;
    *applied = Some(AppliedAddr { ip: params.yiaddr, prefix: params.prefix as u8 });

    let lan_info = LanRouteInfo {
        ifindex: config.ifindex,
        iface_name: config.iface_name.clone(),
        iface_ip: IpAddr::V4(params.yiaddr),
        mac: Some(config.mac_addr),
        prefix: params.prefix as u8,
        mode: LanRouteMode::WanReachable,
    };
    services.route_service.insert_ipv4_lan_route(&config.iface_name, lan_info).await;

    let gateway_ip = match params.options.get(OptionCode::Router) {
        Some(DhcpOption::Router(router_ips)) => router_ips.first().copied(),
        _ => None,
    };
    services.addr_binding.bind_ipv4(
        config.ifindex,
        params.yiaddr,
        gateway_ip,
        params.prefix as u8,
        Some(config.mac_addr),
    );

    if let Some(router_ip) = gateway_ip {
        services
            .route_service
            .insert_ipv4_link_route(
                config.link_id,
                RouteTargetInfo {
                    ifindex: config.ifindex,
                    weight: 1,
                    mac: Some(config.mac_addr),
                    is_docker: false,
                    default_route: config.default_router,
                    iface_name: config.iface_name.clone(),
                    iface_ip: IpAddr::V4(params.yiaddr),
                    gateway_ip: IpAddr::V4(router_ip),
                },
            )
            .await;
        if config.default_router {
            LD_ALL_ROUTERS
                .add_route(RouteInfo {
                    iface_name: config.iface_name.clone(),
                    weight: 1,
                    route: RouteType::Ipv4(router_ip),
                })
                .await;
        } else {
            LD_ALL_ROUTERS.del_route_by_iface(&config.iface_name).await;
        }
    }
}

pub(crate) async fn release(
    applied: &Option<AppliedAddr>,
    config: &DhcpV4ClientServiceRuntimeConfig,
    services: &DhcpV4ClientServices,
) {
    if let Some(prev) = applied {
        run_ip_cmd(&[
            "addr".to_string(),
            "del".to_string(),
            format!("{}/{}", prev.ip, prev.prefix),
            "dev".to_string(),
            config.iface_name.clone(),
        ])
        .await;
    }

    if let Some(session) = services.session.as_ref() {
        session.session_down();
    }

    if config.default_router {
        LD_ALL_ROUTERS.del_route_by_iface(&config.iface_name).await;
    }
    services.route_service.remove_ipv4_link_route(config.link_id).await;
    services.route_service.remove_ipv4_lan_route(&config.iface_name).await;
    services.addr_binding.unbind_ipv4(config.ifindex);
}
