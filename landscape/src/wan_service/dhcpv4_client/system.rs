use landscape_common::SYSCTL_IPV4_RP_FILTER_PATTERN;
use landscape_common::net_proto::dhcp::{
    DhcpV4Option as DhcpOption, DhcpV4OptionCode as OptionCode, DhcpV4Options,
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
        run_ip_cmd(&build_del_args(prev.ip, prev.prefix, &config.iface_name)).await;
    }

    let args = build_replace_args(
        params.yiaddr,
        params.prefix,
        &params.options,
        &config.iface_name,
        params.renew_time,
        params.lease_time,
    );

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
                    dev_only_nexthop: false,
                },
            )
            .await;
    }
}

pub(crate) async fn release(
    applied: &Option<AppliedAddr>,
    config: &DhcpV4ClientServiceRuntimeConfig,
    services: &DhcpV4ClientServices,
) {
    if let Some(prev) = applied {
        run_ip_cmd(&build_del_args(prev.ip, prev.prefix, &config.iface_name)).await;
    }

    if let Some(session) = services.session.as_ref() {
        session.session_down();
    }

    services.route_service.remove_ipv4_link_route(config.link_id).await;
    services.route_service.remove_ipv4_lan_route(&config.iface_name).await;
    services.addr_binding.unbind_ipv4(config.ifindex);
}

fn build_del_args(ip: Ipv4Addr, prefix: u8, iface_name: &str) -> Vec<String> {
    vec![
        "addr".to_string(),
        "del".to_string(),
        format!("{}/{}", ip, prefix),
        "dev".to_string(),
        iface_name.to_string(),
    ]
}

fn build_replace_args(
    yiaddr: Ipv4Addr,
    prefix: u32,
    options: &DhcpV4Options,
    iface_name: &str,
    renew_time: u64,
    lease_time: u64,
) -> Vec<String> {
    let mut args =
        vec!["addr".to_string(), "replace".to_string(), format!("{}/{}", yiaddr, prefix)];

    if let Some(DhcpOption::BroadcastAddr(broadcast)) = options.get(OptionCode::BroadcastAddr) {
        args.extend(["brd".to_string(), format!("{}", broadcast)]);
    }
    args.extend([
        "dev".to_string(),
        iface_name.to_string(),
        "valid_lft".to_string(),
        format!("{}", lease_time),
        "preferred_lft".to_string(),
        format!("{}", renew_time),
    ]);
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_args_include_broadcast_and_lifetimes() {
        let mut options = DhcpV4Options::default();
        options.insert(DhcpOption::BroadcastAddr(Ipv4Addr::new(192, 0, 2, 255)));
        let args = build_replace_args(Ipv4Addr::new(192, 0, 2, 10), 24, &options, "ens4", 50, 100);
        assert_eq!(
            args,
            vec![
                "addr",
                "replace",
                "192.0.2.10/24",
                "brd",
                "192.0.2.255",
                "dev",
                "ens4",
                "valid_lft",
                "100",
                "preferred_lft",
                "50",
            ]
        );
    }

    #[test]
    fn replace_args_omit_broadcast_when_absent() {
        let args = build_replace_args(
            Ipv4Addr::new(192, 0, 2, 10),
            24,
            &DhcpV4Options::default(),
            "ens4",
            50,
            100,
        );
        assert!(!args.contains(&"brd".to_string()));
    }

    #[test]
    fn del_args_format() {
        assert_eq!(
            build_del_args(Ipv4Addr::new(192, 0, 2, 10), 24, "ens4"),
            vec!["addr", "del", "192.0.2.10/24", "dev", "ens4"]
        );
    }
}
