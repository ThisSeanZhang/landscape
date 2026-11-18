use std::{net::IpAddr, panic::AssertUnwindSafe, time::Duration};

use futures::FutureExt;

use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::wan_link::WanLinkV4Model;

use super::LandscapeApp;

impl LandscapeApp {
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down all services...");

        run_shutdown_phase("preserve_critical_ips", || async {
            self.preserve_critical_ips().await;
            tracing::info!("Critical IPs preserved");
        })
        .await;

        run_shutdown_phase("gateway_service", || async {
            match self.managed.gateway_service.shutdown_and_wait(Duration::from_secs(10)).await {
                Ok(()) => tracing::info!("Gateway service stopped"),
                Err(error) => tracing::warn!("Gateway shutdown did not complete: {error}"),
            }
        })
        .await;

        run_shutdown_phase("ddns_service", || async {
            self.managed.ddns_service.shutdown_and_wait(Duration::from_secs(10)).await;
            tracing::info!("DDNS service stopped");
        })
        .await;

        run_shutdown_phase("cert_service", || async {
            self.managed.cert_service.shutdown_and_wait(Duration::from_secs(10)).await;
            tracing::info!("Cert service stopped");
        })
        .await;

        run_shutdown_phase("geo_service", || async {
            self.managed.geo_ip_service.shutdown_and_wait(Duration::from_secs(10)).await;
            self.managed.geo_site_service.shutdown_and_wait(Duration::from_secs(10)).await;
            tracing::info!("Geo services stopped");
        })
        .await;

        run_shutdown_phase("static_nat6_mapping_service", || async {
            self.managed.static_nat6_mapping_service.stop();
            tracing::info!("Static NAT v6 refresh worker stop signal sent");
        })
        .await;

        run_shutdown_phase("stop_service_managers", || async {
            tokio::join!(
                self.managed.wan_link_service.get_service().stop_all(),
                self.managed.route_wan_service.get_service().stop_all(),
                self.managed.route_lan_service.get_service().stop_all(),
                self.managed.dhcp_v4_server_service.get_service().stop_all(),
                self.managed.lan_ipv6_service.get_service().stop_all(),
                self.managed.wifi_service.get_service().stop_all(),
            );
            tracing::info!("All service managers stopped");
        })
        .await;

        run_shutdown_phase("preserve_critical_ips_after_stop", || async {
            self.preserve_critical_ips().await;
            tracing::info!("Critical IPs preserved after service stop");
        })
        .await;

        landscape_ebpf::maps::cleanup_pinned_maps();

        run_shutdown_phase("metric_service", || async {
            if let Err(error) = self.system.metric_service.stop_service().await {
                tracing::warn!(%error, "metric shutdown still draining");
            }
        })
        .await;

        run_shutdown_phase("ebpf_service", || async {
            self.ebpf_service.stop().await;
            tracing::info!("eBPF system service stopped");
        })
        .await;

        run_shutdown_phase("dns_service", || async {
            if let Err(error) = self.system.dns_service.stop().await {
                tracing::warn!(%error, "DNS shutdown incomplete");
            }
        })
        .await;

        // Time sync keeps the clock sane for every other service, stop it last.
        run_shutdown_phase("time_service", || async {
            self.system.time_service.stop().await;
            tracing::info!("Time sync service stopped");
        })
        .await;
    }

    async fn preserve_critical_ips(&self) {
        let dhcp_configs = self.managed.dhcp_v4_server_service.list().await.unwrap_or_default();

        for config in &dhcp_configs {
            if config.enable {
                let ip = IpAddr::V4(config.config.server_ip_addr);
                let prefix_len = config.config.network_mask;
                tracing::info!(
                    "Re-applying DHCPv4 server IP: {ip}/{prefix_len} on {}",
                    config.iface_name
                );
                landscape::netlink::address::set_iface_ip(&config.iface_name, ip, prefix_len).await;
            }
        }

        let wan_links = self.managed.wan_link_service.list().await.unwrap_or_default();

        for link in &wan_links {
            if link.v4.enable
                && let WanLinkV4Model::Static {
                    ipv4: Some(ipv4_addr),
                    ipv4_mask: Some(prefix_len),
                    ..
                } = &link.v4.model
            {
                let ip = IpAddr::V4(*ipv4_addr);
                tracing::info!(
                    "Re-applying WAN static IP: {ip}/{prefix_len} on {}",
                    link.attach_iface_name
                );
                landscape::netlink::address::set_iface_ip(&link.attach_iface_name, ip, *prefix_len)
                    .await;
            }
        }
    }
}

async fn run_shutdown_phase<F, Fut>(name: &'static str, phase: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if let Err(payload) = AssertUnwindSafe(phase()).catch_unwind().await {
        tracing::error!("shutdown phase '{name}' panicked: {payload:?}; continuing shutdown");
    }
}
