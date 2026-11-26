use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::wan_link::WanLinkKind;

use super::LandscapeApp;

impl LandscapeApp {
    pub(crate) async fn remove_iface_services(&self, iface_name: &str) {
        // The WAN link service owns the former per-iface WAN services
        // (v4 / nat / mss / firewall / pd, incl. pppd links): any link
        // attached to this iface goes away with the iface.
        match self.managed.wan_link_service.list().await {
            Ok(links) => {
                for link in links {
                    if link.attach_iface_name == iface_name {
                        if let Err(error) =
                            self.managed.wan_link_service.delete_and_stop_service(link.id).await
                        {
                            tracing::error!(
                                "failed to remove WAN link {} for {iface_name}: {error:?}",
                                link.id
                            );
                        }
                        // A pppd link leaves its ppp device's iface config row
                        // behind: drop it with the link (the cleanup the old
                        // `delete_ppp_iface` cascade used to do).
                        if let WanLinkKind::Pppd { ppp_iface_name, .. } = &link.kind {
                            let _ = self
                                .managed
                                .iface_config_service
                                .delete(ppp_iface_name.clone())
                                .await;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, "listing WAN links for '{iface_name}' failed")
            }
        }

        if let Err(error) =
            self.managed.route_wan_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove route wan service for {iface_name}: {error:?}");
        }
        if let Err(error) = self
            .managed
            .dhcp_v4_server_service
            .delete_and_stop_service(iface_name.to_string())
            .await
        {
            tracing::error!(%error, "deleting DHCPv4 service for '{iface_name}' failed");
        }
        if let Err(error) = self
            .managed
            .lan_ipv6_service
            .delete_and_stop_iface_service(iface_name.to_string())
            .await
        {
            tracing::error!(%error, "deleting LAN IPv6 service for '{iface_name}' failed");
        }
        if let Err(error) =
            self.managed.route_lan_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove route lan service for {iface_name}: {error:?}");
        }
    }
}
