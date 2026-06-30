use std::net::IpAddr;

use landscape_common::global_const::default_router::{RouteInfo, RouteType, LD_ALL_ROUTERS};
use landscape_common::net::MacAddr;
use landscape_common::route::{LanRouteInfo, LanRouteMode, RouteTargetInfo};

use landscape_ebpf::pppoe::pppoe_handle::PppoeHandle;

use crate::pppoe_client::PPPoEClientConfig;
use crate::sys_service::route::IpRouteService;

use super::error::PppoeError;
use super::lcp::LcpPhaseResult;
use super::negotiation::NegotiationResult;

pub(crate) struct EbpfHandle {
    _pppoe_handle: PppoeHandle,
    client_ip: std::net::Ipv4Addr,
    server_ip: std::net::Ipv4Addr,
    server_mac: Vec<u8>,
    ipv6cp_server_id: Option<Vec<u8>>,
    iface_name: String,
    ifindex: u32,
    default_router: bool,
}

impl EbpfHandle {
    pub(crate) async fn shutdown(self, route_service: &IpRouteService) {
        let _ = std::process::Command::new("ip")
            .args(&[
                "addr",
                "del",
                &format!("{}", self.client_ip),
                "peer",
                &format!("{}/32", self.server_ip),
                "dev",
                &self.iface_name,
            ])
            .output();

        let _ = std::process::Command::new("ip")
            .args(&["neigh", "del", &format!("{}", self.server_ip), "dev", &self.iface_name])
            .output();

        let server_linklocal = eui64_linklocal_from_mac(&self.server_mac);
        let _ = std::process::Command::new("ip")
            .args(&["neigh", "del", &format!("{}", server_linklocal), "dev", &self.iface_name])
            .output();

        if let Some(ref iface_id) = self.ipv6cp_server_id {
            if iface_id.len() == 8 {
                let iface_linklocal = iface_id_linklocal(iface_id);
                let _ = std::process::Command::new("ip")
                    .args(&[
                        "neigh",
                        "del",
                        &format!("{}", iface_linklocal),
                        "dev",
                        &self.iface_name,
                    ])
                    .output();
            }
        }

        if self.default_router {
            LD_ALL_ROUTERS.del_route_by_iface(&self.iface_name).await;
        }
        route_service.remove_ipv4_wan_route(&self.iface_name).await;
        route_service.remove_ipv4_lan_route(&self.iface_name).await;
        landscape_ebpf::map_setting::del_ipv4_wan_ip(self.ifindex);

        let _ = std::process::Command::new("ip")
            .args(&["link", "set", "dev", &self.iface_name, "mtu", "1500"])
            .output();

        // PppoeHandle Drop cleans up TC/XDP/SKB state automatically
        drop(self._pppoe_handle);

        tracing::info!("PPPoE system state cleaned up for iface={}", self.iface_name);
    }
}

pub(crate) async fn setup_ebpf(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    nego: &NegotiationResult,
    route_service: &IpRouteService,
) -> Result<EbpfHandle, PppoeError> {
    let mru = lcp.mru.min(config.requested_mru);
    let client_ip = nego.client_ip;
    let server_ip = nego.server_ip;
    let iface_name = &config.iface_name;
    let index = config.index;
    let iface_mac = config.iface_mac;

    tracing::info!(
        "applying native PPPoE system state iface={} client_ip={} peer_ip={} mru={} session_id={}",
        iface_name,
        client_ip,
        server_ip,
        mru,
        lcp.session_id
    );

    landscape_ebpf::map_setting::add_ipv4_wan_ip(
        index,
        client_ip,
        Some(server_ip),
        32,
        Some(iface_mac),
    );

    if let Err(e) = std::process::Command::new("ip")
        .args(&["link", "set", "dev", iface_name, "mtu", &format!("{}", mru)])
        .output()
    {
        tracing::error!("failed to set iface MTU for native PPPoE: {e:?}");
    }

    if let Err(e) = std::process::Command::new("ip")
        .args(&[
            "addr",
            "add",
            &format!("{}", client_ip),
            "peer",
            &format!("{}/32", server_ip),
            "dev",
            iface_name,
        ])
        .output()
    {
        tracing::error!("failed to add PPPoE peer address on iface {}: {e:?}", iface_name);
    }

    let lan_info = LanRouteInfo {
        ifindex: index,
        iface_name: iface_name.clone(),
        iface_ip: IpAddr::V4(client_ip),
        mac: Some(iface_mac),
        prefix: 32,
        mode: LanRouteMode::WanReachable,
    };
    route_service.insert_ipv4_lan_route(iface_name, lan_info).await;
    route_service
        .insert_ipv4_wan_route(
            iface_name,
            RouteTargetInfo {
                ifindex: index,
                weight: 1,
                mac: Some(iface_mac),
                is_docker: false,
                iface_name: iface_name.clone(),
                iface_ip: IpAddr::V4(client_ip),
                default_route: config.default_router,
                gateway_ip: IpAddr::V4(server_ip),
            },
        )
        .await;

    if config.default_router {
        LD_ALL_ROUTERS
            .add_route(RouteInfo {
                iface_name: iface_name.clone(),
                weight: 1,
                route: RouteType::Ipv4(server_ip),
            })
            .await;
    } else {
        LD_ALL_ROUTERS.del_route_by_iface(iface_name).await;
    }

    let server_mac_str = format!("{}", MacAddr::new(
        lcp.server_mac[0], lcp.server_mac[1], lcp.server_mac[2],
        lcp.server_mac[3], lcp.server_mac[4], lcp.server_mac[5],
    ));
    let neigh_result = std::process::Command::new("ip")
        .args(&[
            "neigh",
            "replace",
            &format!("{}", server_ip),
            "lladdr",
            &server_mac_str,
            "dev",
            iface_name,
        ])
        .output();
    match neigh_result {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("add neigh failed for {} on {}: {}", server_ip, iface_name, stderr.trim());
        }
        Err(e) => {
            tracing::error!("add neigh error: {e:?}");
        }
    }

    let server_linklocal = eui64_linklocal_from_mac(&lcp.server_mac);
    let v6_result = std::process::Command::new("ip")
        .args(&[
            "neigh",
            "replace",
            &format!("{}", server_linklocal),
            "lladdr",
            &server_mac_str,
            "dev",
            iface_name,
        ])
        .output();
    match v6_result {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!("add IPv6 neigh failed for {} on {}: {}", server_linklocal, iface_name, stderr.trim());
        }
        Err(e) => {
            tracing::error!("add IPv6 neigh error: {e:?}");
        }
    }

    if let Some(ref server_iface_id) = nego.ipv6cp_server_id {
        if server_iface_id.len() == 8 {
            let iface_linklocal = iface_id_linklocal(server_iface_id);
            let v6_result = std::process::Command::new("ip")
                .args(&[
                    "neigh",
                    "replace",
                    &format!("{}", iface_linklocal),
                    "lladdr",
                    &server_mac_str,
                    "dev",
                    iface_name,
                ])
                .output();
            match v6_result {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::error!(
                        "add IPv6 iface-id neigh failed for {} on {}: {}",
                        iface_linklocal, iface_name, stderr.trim()
                    );
                }
                Err(e) => {
                    tracing::error!("add IPv6 iface-id neigh error: {e:?}");
                }
            }
        }
    }

    let dmac: [u8; 6] = lcp.server_mac[..6].try_into().expect("server MAC must be 6 bytes");
    let tmpl = landscape_ebpf::pppoe::pppoe_handle::PppoeEgressTmpl {
        dmac,
        smac: iface_mac.octets(),
        eth_proto: (0x8864u16).to_be(),
        ver_type: 0x11,
        code: 0x00,
        session_id: lcp.session_id.to_be(),
        ..Default::default()
    };
    let pppoe_handle = landscape_ebpf::pppoe::pppoe_handle::create_pppoe_handle(index, tmpl, mru)
        .map_err(|e| PppoeError::EbpfInitFailed(format!("{}", e)))?;

    tracing::info!(
        "native PPPoE eBPF TC enabled for iface={} session_id={}",
        iface_name,
        lcp.session_id
    );

    Ok(EbpfHandle {
        _pppoe_handle: pppoe_handle,
        client_ip,
        server_ip,
        server_mac: lcp.server_mac.clone(),
        ipv6cp_server_id: nego.ipv6cp_server_id.clone(),
        iface_name: iface_name.clone(),
        ifindex: index,
        default_router: config.default_router,
    })
}

fn eui64_linklocal_from_mac(mac: &[u8]) -> std::net::Ipv6Addr {
    let a = mac[0] ^ 0x02;
    let b = mac[1];
    let c = mac[2];
    let d = mac[3];
    let e = mac[4];
    let f = mac[5];
    std::net::Ipv6Addr::new(
        0xfe80, 0, 0, 0,
        ((a as u16) << 8) | (b as u16),
        ((c as u16) << 8) | 0x00ff,
        0xfe00 | (d as u16),
        ((e as u16) << 8) | (f as u16),
    )
}

fn iface_id_linklocal(id: &[u8]) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::new(
        0xfe80, 0, 0, 0,
        ((id[0] as u16) << 8) | (id[1] as u16),
        ((id[2] as u16) << 8) | (id[3] as u16),
        ((id[4] as u16) << 8) | (id[5] as u16),
        ((id[6] as u16) << 8) | (id[7] as u16),
    )
}
