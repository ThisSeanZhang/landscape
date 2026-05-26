use std::net::IpAddr;

use landscape_common::global_const::default_router::{RouteInfo, RouteType, LD_ALL_ROUTERS};
use landscape_common::net::MacAddr;
use landscape_common::route::{LanRouteInfo, LanRouteMode, RouteTargetInfo};
use tokio::sync::oneshot;

use super::session::PPPoEClientManager;
use super::state::TagValue;
use super::PPPoEClientConfig;
use crate::route::IpRouteService;
use landscape_ebpf::pppoe;

impl PPPoEClientManager {
    pub(crate) async fn enable_ebpf(
        &self,
        config: &PPPoEClientConfig,
        route_service: Option<IpRouteService>,
    ) -> Option<oneshot::Sender<oneshot::Sender<()>>> {
        let mru = if let TagValue::Ack(client_cfg) = &self.lcp_status.client_config {
            client_cfg.mru.min(config.requested_mru)
        } else {
            tracing::error!(
                "cannot enable PPPoE eBPF because local LCP config is not acknowledged"
            );
            return None;
        };

        let client_ifece_id = self.lcp_status.ip6cp_client_id.get_value();
        let server_ifece_id = self.lcp_status.ip6cp_server_id.get_value();

        let Some(client_ip) = self.lcp_status.ipcp_client_ipaddr.get_value() else {
            tracing::error!("cannot enable PPPoE eBPF because local IPv4 address is missing");
            return None;
        };
        let Some(server_ip) = self.lcp_status.ipcp_server_ipaddr.get_value() else {
            tracing::error!("cannot enable PPPoE eBPF because peer IPv4 address is missing");
            return None;
        };

        let super::state::PPPoEConnectState::SessionConfirm { server_mac_addr, session_id } =
            &self.pppoe_status
        else {
            tracing::error!("cannot enable PPPoE eBPF without an active session");
            return None;
        };
        tracing::info!(
            "server_ip: {:?}, client_ip: {:?}, server_ifece_id: {:?}, client_ipv6_id: {:?}",
            server_ip,
            client_ip,
            server_ifece_id,
            client_ifece_id
        );

        let (outside_notice_tx, outside_notice_rx) = oneshot::channel::<oneshot::Sender<()>>();
        let index = config.index;
        let iface_name = config.iface_name.clone();
        let iface_mac = config.iface_mac;
        let default_router = config.default_router;
        let session_id = *session_id;
        let server_mac_addr = server_mac_addr.clone();
        tokio::spawn(async move {
            tracing::info!(
                "applying native PPPoE system state iface={} client_ip={} peer_ip={} mru={} session_id={}",
                iface_name,
                client_ip,
                server_ip,
                mru,
                session_id
            );
            landscape_ebpf::map_setting::add_ipv4_wan_ip(
                index,
                client_ip,
                Some(server_ip),
                32,
                Some(iface_mac),
            );
            if let Err(e) = std::process::Command::new("ip")
                .args(&["link", "set", "dev", &iface_name, "mtu", &format!("{}", mru)])
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
                    &iface_name,
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
            if let Some(route_service) = route_service.as_ref() {
                route_service.insert_ipv4_lan_route(&iface_name, lan_info).await;
                route_service
                    .insert_ipv4_wan_route(
                        &iface_name,
                        RouteTargetInfo {
                            ifindex: index,
                            weight: 1,
                            mac: Some(iface_mac),
                            is_docker: false,
                            iface_name: iface_name.clone(),
                            iface_ip: IpAddr::V4(client_ip),
                            default_route: default_router,
                            gateway_ip: IpAddr::V4(server_ip),
                        },
                    )
                    .await;
            }

            if default_router {
                LD_ALL_ROUTERS
                    .add_route(RouteInfo {
                        iface_name: iface_name.clone(),
                        weight: 1,
                        route: RouteType::Ipv4(server_ip),
                    })
                    .await;
            } else {
                LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
            }

            let neight_run_result = std::process::Command::new("ip")
                .args(&[
                    "neigh",
                    "add",
                    &format!("{}", server_ip),
                    "lladdr",
                    &format!(
                        "{}",
                        MacAddr::new(
                            server_mac_addr[0],
                            server_mac_addr[1],
                            server_mac_addr[2],
                            server_mac_addr[3],
                            server_mac_addr[4],
                            server_mac_addr[5],
                        )
                    ),
                    "dev",
                    &iface_name,
                ])
                .output();
            if let Err(e) = neight_run_result {
                tracing::error!("add neigh error: {e:?}");
            }
            let notise = pppoe::pppoe_tc::create_pppoe_tc_ebpf_3(index, session_id, mru).await;
            let outside_callback = outside_notice_rx.await;

            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Ok(()) = notise.send(tx) {
                if let Err(e) = rx.await {
                    tracing::error!("wait ebpf tc detach fail: {e:?}");
                }
            }

            if let Err(e) = std::process::Command::new("ip")
                .args(&[
                    "addr",
                    "del",
                    &format!("{}", client_ip),
                    "peer",
                    &format!("{}/32", server_ip),
                    "dev",
                    &iface_name,
                ])
                .output()
            {
                tracing::error!(
                    "failed to remove PPPoE peer address on iface {}: {e:?}",
                    iface_name
                );
            }

            if default_router {
                LD_ALL_ROUTERS.del_route_by_iface(&iface_name).await;
            }
            if let Some(route_service) = route_service.as_ref() {
                route_service.remove_ipv4_wan_route(&iface_name).await;
                route_service.remove_ipv4_lan_route(&iface_name).await;
            }
            landscape_ebpf::map_setting::del_ipv4_wan_ip(index);
            if let Err(e) = std::process::Command::new("ip")
                .args(&["link", "set", "dev", &iface_name, "mtu", "1500"])
                .output()
            {
                tracing::error!("failed to restore iface MTU after PPPoE teardown: {e:?}");
            }

            if let Ok(callback) = outside_callback {
                let _ = callback.send(());
            }
            tracing::info!("native PPPoE system state cleaned up for iface={}", iface_name);
        });

        Some(outside_notice_tx)
    }
}
