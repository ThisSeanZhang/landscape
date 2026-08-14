use std::net::IpAddr;

use landscape_common::global_const::default_router::{RouteInfo, RouteType, LD_ALL_ROUTERS};
use landscape_common::net::MacAddr;
use landscape_common::sys_service::route_service::{LanRouteInfo, LanRouteMode, RouteTargetInfo};

use landscape_ebpf::pppoe::pppoe_handle::PppoeHandle;

use crate::get_existing_linklocal;
use crate::pppoe_client::PPPoEClientConfig;
use crate::sys_service::route::IpRouteService;

use super::error::PppoeError;
use super::lcp::LcpPhaseResult;
use super::negotiation::NegotiationResult;

pub(crate) struct SessionHandle {
    _pppoe_handle: PppoeHandle,
    client_ip: std::net::Ipv4Addr,
    server_ip: std::net::Ipv4Addr,
    server_mac: Vec<u8>,
    ipv6cp_server_id: Option<Vec<u8>>,
    ipv6cp_client_linklocal: Option<std::net::Ipv6Addr>,
    prev_ipv6_linklocal: Option<std::net::Ipv6Addr>,
    iface_name: String,
    ifindex: u32,
    default_router: bool,
}

impl SessionHandle {
    pub(crate) async fn shutdown(self, route_service: &IpRouteService) {
        let _ = std::process::Command::new("ip")
            .args([
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
            .args(["neigh", "del", &format!("{}", self.server_ip), "dev", &self.iface_name])
            .output();

        let server_linklocal = eui64_linklocal_from_mac(&self.server_mac);
        let _ = std::process::Command::new("ip")
            .args(["neigh", "del", &format!("{}", server_linklocal), "dev", &self.iface_name])
            .output();

        if let Some(ref iface_id) = self.ipv6cp_server_id {
            if iface_id.len() == 8 {
                let iface_linklocal = iface_id_linklocal(iface_id);
                let _ = std::process::Command::new("ip")
                    .args([
                        "neigh",
                        "del",
                        &format!("{}", iface_linklocal),
                        "dev",
                        &self.iface_name,
                    ])
                    .output();
            }
        }

        if let Some(ref linklocal) = self.ipv6cp_client_linklocal {
            let _ = std::process::Command::new("ip")
                .args(["-6", "addr", "del", &format!("{}/64", linklocal), "dev", &self.iface_name])
                .output();
        }

        if let Some(ref prev) = self.prev_ipv6_linklocal {
            let _ = std::process::Command::new("ip")
                .args(["-6", "addr", "add", &format!("{}/64", prev), "dev", &self.iface_name])
                .output();
        }

        if self.default_router {
            LD_ALL_ROUTERS.del_route_by_iface(&self.iface_name).await;
        }
        route_service.remove_ipv4_wan_route(&self.iface_name).await;
        route_service.remove_ipv4_lan_route(&self.iface_name).await;
        landscape_ebpf::map_setting::del_ipv4_wan_ip(self.ifindex);

        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", &self.iface_name, "mtu", "1500"])
            .output();

        // PppoeHandle Drop cleans up TC/XDP/SKB state automatically
        drop(self._pppoe_handle);

        tracing::info!("PPPoE system state cleaned up for iface={}", self.iface_name);
    }
}

pub(crate) async fn create_session(
    config: &PPPoEClientConfig,
    lcp: &LcpPhaseResult,
    nego: &NegotiationResult,
    route_service: &IpRouteService,
) -> Result<SessionHandle, PppoeError> {
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
        .args(["link", "set", "dev", iface_name, "mtu", &format!("{}", mru)])
        .output()
    {
        tracing::error!("failed to set iface MTU for native PPPoE: {e:?}");
    }

    if let Err(e) = std::process::Command::new("ip")
        .args([
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

    let server_mac_str = format!(
        "{}",
        MacAddr::new(
            lcp.server_mac[0],
            lcp.server_mac[1],
            lcp.server_mac[2],
            lcp.server_mac[3],
            lcp.server_mac[4],
            lcp.server_mac[5],
        )
    );
    let neigh_result = std::process::Command::new("ip")
        .args([
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
            tracing::error!(
                "add neigh failed for {} on {}: {}",
                server_ip,
                iface_name,
                stderr.trim()
            );
        }
        Err(e) => {
            tracing::error!("add neigh error: {e:?}");
        }
    }

    let server_linklocal = eui64_linklocal_from_mac(&lcp.server_mac);
    let v6_result = std::process::Command::new("ip")
        .args([
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
            tracing::error!(
                "add IPv6 neigh failed for {} on {}: {}",
                server_linklocal,
                iface_name,
                stderr.trim()
            );
        }
        Err(e) => {
            tracing::error!("add IPv6 neigh error: {e:?}");
        }
    }

    if let Some(ref server_iface_id) = nego.ipv6cp_server_id {
        if server_iface_id.len() == 8 {
            let iface_linklocal = iface_id_linklocal(server_iface_id);
            let v6_result = std::process::Command::new("ip")
                .args([
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
                        iface_linklocal,
                        iface_name,
                        stderr.trim()
                    );
                }
                Err(e) => {
                    tracing::error!("add IPv6 iface-id neigh error: {e:?}");
                }
            }
        }
    }

    let (prev_linklocal_v6, client_linklocal_v6) =
        setup_linklocal(iface_name, nego.ipv6cp_client_id.as_deref());

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

    Ok(SessionHandle {
        _pppoe_handle: pppoe_handle,
        client_ip,
        server_ip,
        server_mac: lcp.server_mac.clone(),
        ipv6cp_server_id: nego.ipv6cp_server_id.clone(),
        ipv6cp_client_linklocal: client_linklocal_v6,
        prev_ipv6_linklocal: prev_linklocal_v6,
        iface_name: iface_name.clone(),
        ifindex: index,
        default_router: config.default_router,
    })
}

fn setup_linklocal(
    iface_name: &str,
    client_iface_id: Option<&[u8]>,
) -> (Option<std::net::Ipv6Addr>, Option<std::net::Ipv6Addr>) {
    let prev = get_existing_linklocal(iface_name);
    let mut new = None;

    if let Some(iface_id) = client_iface_id {
        if iface_id.len() == 8 {
            let addr = iface_id_linklocal(iface_id);

            let _ = std::process::Command::new("ip")
                .args(["-6", "addr", "flush", "dev", iface_name, "scope", "link"])
                .output();

            let result = std::process::Command::new("ip")
                .args(["-6", "addr", "add", &format!("{}/64", addr), "dev", iface_name])
                .output();
            match result {
                Ok(output) if output.status.success() => {
                    tracing::info!(iface = %iface_name, linklocal = %addr, "IPv6 link-local address set from IPv6CP");
                    new = Some(addr);
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::error!(
                        "add IPv6 link-local {} on {}: {}",
                        addr,
                        iface_name,
                        stderr.trim()
                    );
                }
                Err(e) => {
                    tracing::error!("add IPv6 link-local error: {e:?}");
                }
            }
        }
    }

    (prev, new)
}

fn eui64_linklocal_from_mac(mac: &[u8]) -> std::net::Ipv6Addr {
    let a = mac[0] ^ 0x02;
    let b = mac[1];
    let c = mac[2];
    let d = mac[3];
    let e = mac[4];
    let f = mac[5];
    std::net::Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        ((a as u16) << 8) | (b as u16),
        ((c as u16) << 8) | 0x00ff,
        0xfe00 | (d as u16),
        ((e as u16) << 8) | (f as u16),
    )
}

fn iface_id_linklocal(id: &[u8]) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        ((id[0] as u16) << 8) | (id[1] as u16),
        ((id[2] as u16) << 8) | (id[3] as u16),
        ((id[4] as u16) << 8) | (id[5] as u16),
        ((id[6] as u16) << 8) | (id[7] as u16),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLACE_IFACE: &str = "dum_ll_replace";
    const NO_OLD_IFACE: &str = "dum_ll_no_old";
    const NO_NEW_IFACE: &str = "dum_ll_no_new";
    const INVALID_ID_IFACE: &str = "dum_ll_bad_id";
    const RESTORE_IFACE: &str = "dum_ll_restore";
    const OLD_ID: [u8; 8] = [0xaa, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01];
    const NEW_ID: [u8; 8] = [0xbb, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x02];

    fn old_addr() -> std::net::Ipv6Addr {
        iface_id_linklocal(&OLD_ID)
    }

    fn new_addr() -> std::net::Ipv6Addr {
        iface_id_linklocal(&NEW_ID)
    }

    fn can_create_dummy(iface: &str) -> bool {
        teardown(iface);
        let created = std::process::Command::new("ip")
            .args(["link", "add", iface, "type", "dummy"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !created {
            eprintln!("[SKIP] cannot create dummy interface (need root?)");
            return false;
        }
        let up = std::process::Command::new("ip")
            .args(["link", "set", iface, "up"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !up {
            eprintln!("[SKIP] cannot set dummy interface up");
            teardown(iface);
            return false;
        }
        let _ = std::process::Command::new("ip")
            .args(["link", "set", iface, "addrgenmode", "none"])
            .status();
        true
    }

    fn setup_with_addr(iface: &str, addr: std::net::Ipv6Addr) -> bool {
        std::process::Command::new("ip")
            .args(["-6", "addr", "add", &format!("{}/64", addr), "dev", iface])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn remove_addr(iface: &str, addr: std::net::Ipv6Addr) -> bool {
        std::process::Command::new("ip")
            .args(["-6", "addr", "del", &format!("{}/64", addr), "dev", iface])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn teardown(iface: &str) {
        let _ = std::process::Command::new("ip").args(["link", "del", iface]).output();
    }

    #[test]
    fn test_setup_linklocal_replace() {
        let iface = REPLACE_IFACE;
        if !can_create_dummy(iface) {
            return;
        }
        assert!(setup_with_addr(iface, old_addr()), "should set old link-local");
        assert_eq!(
            get_existing_linklocal(iface),
            Some(old_addr()),
            "old address should be present"
        );

        let (prev, new) = setup_linklocal(iface, Some(&NEW_ID));
        assert_eq!(prev, Some(old_addr()), "should return old as prev");
        assert_eq!(new, Some(new_addr()), "should return new addr");
        assert_eq!(
            get_existing_linklocal(iface),
            Some(new_addr()),
            "only new link-local should remain"
        );

        teardown(iface);
    }

    #[test]
    fn test_setup_linklocal_no_old() {
        let iface = NO_OLD_IFACE;
        if !can_create_dummy(iface) {
            return;
        }

        let (prev, new) = setup_linklocal(iface, Some(&NEW_ID));
        assert_eq!(new, Some(new_addr()), "should set new addr");
        assert_eq!(
            get_existing_linklocal(iface),
            Some(new_addr()),
            "new link-local should be on interface"
        );
        if let Some(prev) = prev {
            assert_ne!(prev, new_addr(), "prev should differ from new");
        }

        teardown(iface);
    }

    #[test]
    fn test_setup_linklocal_no_new() {
        let iface = NO_NEW_IFACE;
        if !can_create_dummy(iface) {
            return;
        }
        assert!(setup_with_addr(iface, old_addr()), "should set old link-local");

        let (prev, new) = setup_linklocal(iface, None);
        assert_eq!(prev, Some(old_addr()), "should capture old as prev");
        assert_eq!(new, None, "new should be None");
        assert_eq!(
            get_existing_linklocal(iface),
            Some(old_addr()),
            "old address should still be present"
        );

        teardown(iface);
    }

    #[test]
    fn test_setup_linklocal_invalid_id() {
        let iface = INVALID_ID_IFACE;
        if !can_create_dummy(iface) {
            return;
        }

        let before = get_existing_linklocal(iface);

        let short_id: &[u8] = &[0xaa, 0xbb];
        let (_prev, new) = setup_linklocal(iface, Some(short_id));
        assert_eq!(new, None, "new should be None for invalid id length");
        assert_eq!(
            get_existing_linklocal(iface),
            before,
            "interface should be unchanged for invalid id"
        );

        teardown(iface);
    }

    #[test]
    fn test_linklocal_restore() {
        let iface = RESTORE_IFACE;
        if !can_create_dummy(iface) {
            return;
        }
        assert!(setup_with_addr(iface, old_addr()), "should set old link-local");

        let (prev, _new) = setup_linklocal(iface, Some(&NEW_ID));
        assert_eq!(prev, Some(old_addr()));
        assert_eq!(
            get_existing_linklocal(iface),
            Some(new_addr()),
            "new link-local should be on interface"
        );

        assert!(remove_addr(iface, new_addr()), "should remove new addr");
        if let Some(prev) = prev {
            assert!(setup_with_addr(iface, prev), "should restore old addr");
        }
        assert_eq!(
            get_existing_linklocal(iface),
            Some(old_addr()),
            "old link-local should be restored"
        );

        teardown(iface);
    }
}
