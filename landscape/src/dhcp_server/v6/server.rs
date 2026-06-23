use std::net::Ipv6Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::dhcp::v6_server::config::{
    DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
};
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::net::MacAddr;
use tokio::sync::Mutex;

use super::dhcp_v6_status::DhcpV6AssignStatus;
use crate::ipv6::prefix::{ICMPv6ConfigInfo, PdDelegationParent};

use super::types::{DHCPv6NACache, DHCPv6PDCache};

pub struct DHCPv6Server {
    pub server_duid: Vec<u8>,
    pub na_config: Option<DHCPv6IANAConfig>,
    pub pd_config: Option<DHCPv6IAPDConfig>,
    pub status: Arc<Mutex<DhcpV6AssignStatus>>,
}

impl DHCPv6Server {
    pub fn init(
        config: &DHCPv6ServerConfig,
        server_duid: Vec<u8>,
        status: Arc<Mutex<DhcpV6AssignStatus>>,
    ) -> Self {
        DHCPv6Server {
            server_duid,
            na_config: config.ia_na.clone(),
            pd_config: config.ia_pd.clone(),
            status,
        }
    }

    pub async fn offer_na_suffix(
        &self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
    ) -> Option<u64> {
        self.status.lock().await.offer_na_suffix(client_duid, mac, hostname)
    }

    pub async fn confirm_na(&self, client_duid: &[u8]) -> bool {
        self.status.lock().await.confirm_na(client_duid)
    }

    pub async fn release_na(&self, client_duid: &[u8]) {
        self.status.lock().await.release_na(client_duid)
    }

    pub async fn clean_expired_na(&self) -> bool {
        self.status.lock().await.clean_expired_na()
    }

    pub async fn offer_pd_index(
        &self,
        client_duid: &[u8],
        qualifying_prefixes: &[(Ipv6Addr, u8)],
    ) -> Option<u32> {
        self.status.lock().await.offer_pd_index(client_duid, qualifying_prefixes)
    }

    pub async fn confirm_pd(&self, client_duid: &[u8]) -> bool {
        self.status.lock().await.confirm_pd(client_duid)
    }

    pub async fn release_pd(&self, client_duid: &[u8]) -> Option<DHCPv6PDCache> {
        self.status.lock().await.release_pd(client_duid)
    }

    pub async fn clean_expired_pd(&self) -> Vec<DHCPv6PDCache> {
        self.status.lock().await.clean_expired_pd()
    }

    pub async fn get_na_offer(&self, client_duid: &[u8]) -> Option<DHCPv6NACache> {
        self.status.lock().await.na_offered.get(client_duid).cloned()
    }

    pub async fn has_na_offer(&self, client_duid: &[u8]) -> bool {
        self.status.lock().await.na_offered.contains_key(client_duid)
    }

    pub async fn get_pd_offer(&self, client_duid: &[u8]) -> Option<DHCPv6PDCache> {
        self.status.lock().await.pd_offered.get(client_duid).cloned()
    }

    pub async fn has_pd_offer(&self, client_duid: &[u8]) -> bool {
        self.status.lock().await.pd_offered.contains_key(client_duid)
    }

    pub async fn get_offered_info(
        &self,
        na_prefixes: &[(Ipv6Addr, u8)],
        pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> DHCPv6OfferInfo {
        self.status.lock().await.get_offered_info(na_prefixes, pd_prefixes)
    }

    pub async fn get_qualifying_na_prefixes(
        &self,
        runtime_sources: &[Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>],
        static_infos: &[ICMPv6ConfigInfo],
    ) -> Vec<(Ipv6Addr, u8)> {
        super::dhcp_v6_status::compute_qualifying_na_prefixes(
            &self.na_config,
            runtime_sources,
            static_infos,
        )
    }

    pub async fn get_qualifying_pd_prefixes(
        &self,
        pd_delegation_static: &[PdDelegationParent],
        pd_delegation_dynamic: &[Arc<ArcSwap<Option<PdDelegationParent>>>],
    ) -> Vec<(Ipv6Addr, u8)> {
        super::dhcp_v6_status::compute_qualifying_pd_prefixes(
            &self.pd_config,
            pd_delegation_static,
            pd_delegation_dynamic,
        )
    }

    pub async fn refresh_offer_info(
        &self,
        ra_pd_runtime_sources: &[Arc<ArcSwap<Option<ICMPv6ConfigInfo>>>],
        ra_static_infos: &[ICMPv6ConfigInfo],
        pd_delegation_static: &[PdDelegationParent],
        pd_delegation_dynamic: &[Arc<ArcSwap<Option<PdDelegationParent>>>],
    ) {
        let na = super::dhcp_v6_status::compute_qualifying_na_prefixes(
            &self.na_config,
            ra_pd_runtime_sources,
            ra_static_infos,
        );
        let pd = super::dhcp_v6_status::compute_qualifying_pd_prefixes(
            &self.pd_config,
            pd_delegation_static,
            pd_delegation_dynamic,
        );
        let mut status = self.status.lock().await;
        status.last_offer_info = status.get_offered_info(&na, &pd);
    }
}
