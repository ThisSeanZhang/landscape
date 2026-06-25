use std::net::Ipv6Addr;
use std::sync::Arc;

use landscape_common::dhcp::v6_server::config::{
    DHCPv6IANAConfig, DHCPv6IAPDConfig, DHCPv6ServerConfig,
};
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::net::MacAddr;
use tokio::sync::Mutex;

use super::lease_allocator::{DhcpV6LeaseAllocator, NaAllocSource, PdRouteCleanup};
use crate::ipv6::prefix::{Assignment, ICMPv6ConfigInfo, PdDelegationParent};

use super::types::{DHCPv6NACache, DHCPv6PDCache};

pub struct DHCPv6Server {
    pub server_duid: Vec<u8>,
    pub na_config: Option<DHCPv6IANAConfig>,
    pub pd_config: Option<DHCPv6IAPDConfig>,
    pub allocator: Arc<Mutex<DhcpV6LeaseAllocator>>,
}

impl DHCPv6Server {
    pub fn init(
        config: &DHCPv6ServerConfig,
        server_duid: Vec<u8>,
        allocator: Arc<Mutex<DhcpV6LeaseAllocator>>,
    ) -> Self {
        DHCPv6Server {
            server_duid,
            na_config: config.ia_na.clone(),
            pd_config: config.ia_pd.clone(),
            allocator,
        }
    }

    pub async fn offer_na_suffix(
        &self,
        client_duid: &[u8],
        mac: Option<MacAddr>,
        hostname: Option<String>,
    ) -> Option<u64> {
        self.allocator.lock().await.offer_na(client_duid, mac, hostname).map(|lease| lease.suffix)
    }

    pub async fn confirm_na(&self, client_duid: &[u8]) -> bool {
        self.allocator.lock().await.confirm_na(client_duid)
    }

    pub async fn consume_prev_suffix(&self, client_duid: &[u8]) {
        self.allocator.lock().await.consume_prev_suffix(client_duid);
    }

    pub async fn release_na(&self, client_duid: &[u8]) -> Option<DHCPv6NACache> {
        self.allocator.lock().await.release_na(client_duid)
    }

    pub async fn clean_expired_na(&self) -> Vec<DHCPv6NACache> {
        self.allocator.lock().await.clean_expired_na()
    }

    pub async fn offer_pd_index(
        &self,
        client_duid: &[u8],
        qualifying_prefixes: &[(Ipv6Addr, u8)],
    ) -> Option<u32> {
        self.allocator.lock().await.offer_pd_index(client_duid, qualifying_prefixes)
    }

    pub async fn confirm_pd(&self, client_duid: &[u8]) -> bool {
        self.allocator.lock().await.confirm_pd(client_duid)
    }

    pub async fn release_pd(&self, client_duid: &[u8]) -> Option<DHCPv6PDCache> {
        self.allocator.lock().await.release_pd(client_duid)
    }

    pub async fn clean_expired_pd(&self) -> Vec<DHCPv6PDCache> {
        self.allocator.lock().await.clean_expired_pd()
    }

    pub async fn get_na_offer(&self, client_duid: &[u8]) -> Option<DHCPv6NACache> {
        self.allocator.lock().await.get_na_offer(client_duid)
    }

    pub async fn has_na_offer(&self, client_duid: &[u8]) -> bool {
        self.allocator.lock().await.has_na_offer(client_duid)
    }

    pub async fn get_suffix_owner(&self, suffix: u64) -> Option<NaAllocSource> {
        self.allocator.lock().await.get_suffix_owner(suffix)
    }

    pub async fn get_pd_offer(&self, client_duid: &[u8]) -> Option<DHCPv6PDCache> {
        self.allocator.lock().await.get_pd_offer(client_duid)
    }

    pub async fn has_pd_offer(&self, client_duid: &[u8]) -> bool {
        self.allocator.lock().await.has_pd_offer(client_duid)
    }

    pub async fn get_offered_info(
        &self,
        na_prefixes: &[(Ipv6Addr, u8)],
        pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> DHCPv6OfferInfo {
        self.allocator.lock().await.lease_view(na_prefixes, pd_prefixes)
    }

    pub async fn get_pd_route_info(
        &self,
        client_duid: &[u8],
    ) -> Option<(Vec<(Ipv6Addr, u8)>, u32, u32)> {
        self.allocator.lock().await.get_pd_route_info(client_duid)
    }

    pub async fn update_pd_active_routes(
        &self,
        client_duid: &[u8],
        client_addr: Ipv6Addr,
        routes: Vec<(Ipv6Addr, u8)>,
    ) -> Option<Vec<(Ipv6Addr, u8)>> {
        self.allocator.lock().await.update_pd_active_routes(client_duid, client_addr, routes)
    }

    pub async fn reconcile_pd_routes(
        &self,
        current_pd_prefixes: &[(Ipv6Addr, u8)],
    ) -> Vec<PdRouteCleanup> {
        self.allocator.lock().await.reconcile_pd_routes(current_pd_prefixes)
    }

    pub async fn get_qualifying_na_prefixes(
        &self,
        assignment: &Assignment<ICMPv6ConfigInfo>,
    ) -> Vec<(Ipv6Addr, u8)> {
        super::dhcp_v6_status::compute_qualifying_na_prefixes(&self.na_config, assignment)
    }

    pub async fn get_qualifying_pd_prefixes(
        &self,
        assignment: &Assignment<PdDelegationParent>,
    ) -> Vec<(Ipv6Addr, u8)> {
        super::dhcp_v6_status::compute_qualifying_pd_prefixes(&self.pd_config, assignment)
    }

    pub async fn current_offer_info(
        &self,
        na: &Assignment<ICMPv6ConfigInfo>,
        pd: &Assignment<PdDelegationParent>,
    ) -> DHCPv6OfferInfo {
        let na = super::dhcp_v6_status::compute_qualifying_na_prefixes(&self.na_config, na);
        let pd = super::dhcp_v6_status::compute_qualifying_pd_prefixes(&self.pd_config, pd);
        self.get_offered_info(&na, &pd).await
    }

    pub async fn sync_prefixes(
        &self,
        na: &Assignment<ICMPv6ConfigInfo>,
        pd: &Assignment<PdDelegationParent>,
    ) {
        let na = super::dhcp_v6_status::compute_qualifying_na_prefixes(&self.na_config, na);
        let pd = super::dhcp_v6_status::compute_qualifying_pd_prefixes(&self.pd_config, pd);
        self.allocator.lock().await.set_prefixes(na, pd);
    }
}
