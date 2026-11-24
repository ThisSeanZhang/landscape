//! The per-link WAN dataplane.
//!
//! One [`WanLinkDataplane`] exists per WAN link and owns the link's
//! whole eBPF chain lifecycle: the four root programs (XDP from-WAN /
//! from-LAN, TC WAN-ingress / WAN-egress) registered under the link's
//! chain id in the shared root prog arrays, the per-direction stage
//! tables, the link's from-LAN exit programs, and the link's WAN address
//! publications in the dispatch trie.  Dropping the object tears all of
//! that down (see [`Drop`]).
//!
//! The shared, link-independent substrate (trie, intro seed, from-WAN
//! exit skeletons, root-array shells) lives in
//! [`crate::route_backbone::RouteBackbone`]. The two
//! hook planes' stage plumbing (state, root loaders, relinks,
//! loader-facing views) lives in the [`xdp`] and [`tc`] submodules.

mod from_lan;
mod gateway_arp;
mod tc;
mod xdp;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::fd::AsFd;
use std::sync::Arc;
use std::sync::Mutex;

use landscape_common::ebpf::DataplaneGuard;
use landscape_common::net::MacAddr;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::wan_chain::dataplane::PppoeEgressTmpl;
use libbpf_rs::MapCore;

use crate::bpf_error::LandscapeEbpfError;
use crate::bpf_error::LdEbpfResult;
use crate::maps;
use crate::maps::wan_trie::dispatcher::WanTrieDispatcher;
use crate::route_backbone::RouteBackbone;
use crate::route_backbone::pinned_map;

use from_lan::WanEgressBinding;
use gateway_arp::GatewayArpState;
use tc::TcChainState;
use tc::TcChainView;
use xdp::XdpChainState;
use xdp::XdpChainView;

pub(crate) use tc::TcPppoeExitGuard;

/// The skeleton-side template type generated from the BPF C header.
pub(crate) type BpfPppoeTmpl = crate::skel::tc_wan_pppoe_exit::types::pppoe_egress_tmpl;

/// The common and BPF-side templates must stay layout-identical; the
/// field-by-field conversion below relies on it.
const _: () = {
    assert!(std::mem::size_of::<PppoeEgressTmpl>() == std::mem::size_of::<BpfPppoeTmpl>(),);
};

fn to_bpf_tmpl(tmpl: &PppoeEgressTmpl) -> BpfPppoeTmpl {
    BpfPppoeTmpl {
        dmac: tmpl.dmac,
        smac: tmpl.smac,
        eth_proto: tmpl.eth_proto,
        ver_type: tmpl.ver_type,
        code: tmpl.code,
        session_id: tmpl.session_id,
        length: tmpl.length,
        protocol: tmpl.protocol,
    }
}

/// WAN address binding used for root configuration and dispatch-trie publication.
#[derive(Clone, Copy)]
struct AddrBind {
    ifindex: u32,
    addr: IpAddr,
    gateway: Option<IpAddr>,
    mask: u8,
    mac: Option<MacAddr>,
    is_pppoe: bool,
}

#[derive(Clone, Copy)]
enum BindKind {
    L2,
    NativePppoe,
    Ppp,
}

#[derive(Default)]
struct Inner {
    ifindex: Option<u32>,
    has_eth_header: bool,
    is_ppp: bool,
    v4: Option<AddrBind>,
    v6: Option<AddrBind>,
    closed: bool,
    published_egress_binding: Option<WanEgressBinding>,
    gateway_arp: GatewayArpState,
    xdp: XdpChainState,
    tc: TcChainState,
}

/// The per-link WAN dataplane: roots, stage tables and trie
/// publications of exactly one WAN link.  Constructed when the link's
/// service starts, dropped when it stops; [`Drop`] performs the
/// teardown unless [`close`](WanLinkDataplane::close) already ran.
pub struct WanLinkDataplane {
    backbone: Arc<RouteBackbone>,
    id: u16,
    inner: Mutex<Inner>,
    /// Chain-private from-LAN exits, shared by this chain's roots and stages.
    xdp_lan_exit_map: libbpf_rs::MapHandle,
    tc_wan_egress_exit_map: libbpf_rs::MapHandle,
}

impl WanLinkDataplane {
    /// Load the link's four chain roots and register them under `id`
    /// in the shared root prog arrays.  `ifindex`/`has_eth_header` seed
    /// the pairing state (both are refreshed by later `observe` calls).
    pub fn new(
        backbone: Arc<RouteBackbone>,
        id: u16,
        ifindex: Option<u32>,
        has_eth_header: bool,
    ) -> LdEbpfResult<Arc<Self>> {
        let xdp_lan_exit_map = Self::create_xdp_lan_exit_map()?;
        let (tc_wan_egress_exit_map, tc_plain_exit) = Self::create_tc_wan_egress_exit()?;
        let mut inner = Inner { ifindex, has_eth_header, ..Inner::default() };
        inner.tc.plain_exit = Some(tc_plain_exit);
        let dp = Arc::new(Self {
            backbone,
            id,
            inner: Mutex::new(inner),
            xdp_lan_exit_map,
            tc_wan_egress_exit_map,
        });
        {
            let mut inner = dp.inner.lock().unwrap();
            inner.xdp.wan_root = Some(Self::create_wan_root(&dp.backbone, id)?);
            let l3_offset = if has_eth_header { 14 } else { 0 };
            inner.tc.ingress_root = Some(Self::create_ingress_root(&dp.backbone, id, l3_offset)?);
            dp.refresh_from_lan_roots(&mut inner)?;
        }
        Ok(dp)
    }

    /// This link's chain id.
    pub fn id(&self) -> u16 {
        self.id
    }

    pub(crate) fn backbone(&self) -> &Arc<RouteBackbone> {
        &self.backbone
    }

    /// Point a skeleton's from-LAN XDP exit slot at this chain's exit map.
    pub(crate) fn reuse_xdp_lan_exit_map(
        &self,
        map: &mut libbpf_rs::OpenMapMut<'_>,
    ) -> LdEbpfResult<()> {
        map.reuse_fd(self.xdp_lan_exit_map.as_fd()).map_err(|source| LandscapeEbpfError::Context {
            context: "reuse per-chain XDP from-LAN exit map failed".to_string(),
            source,
        })
    }

    /// Point a skeleton's from-LAN TC exit slot at this chain's exit map.
    pub(crate) fn reuse_tc_wan_egress_exit_map(
        &self,
        map: &mut libbpf_rs::OpenMapMut<'_>,
    ) -> LdEbpfResult<()> {
        map.reuse_fd(self.tc_wan_egress_exit_map.as_fd()).map_err(|source| {
            LandscapeEbpfError::Context {
                context: "reuse per-chain TC from-LAN exit map failed".to_string(),
                source,
            }
        })
    }

    fn sync_wan_binding(&self, inner: &mut Inner) {
        inner.sync_gateway_arp_target();
        inner.sync_gateway_ns_target();
        if let Err(err) = self.refresh_from_lan_roots(inner) {
            tracing::warn!(chain = self.id, error = %err, "refreshing from-LAN roots failed");
        }
    }

    /// Refresh the chain ↔ ifindex pairing, tolerating re-dial churn:
    /// sections restart in unspecified order after a re-dial, so every
    /// entry point refreshes the pairing instead of validating it.
    pub fn observe(&self, ifindex: u32, has_eth_header: bool) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        self.observe_interface(&mut inner, ifindex, has_eth_header);
        self.sync_wan_binding(&mut inner);
    }

    fn observe_interface(&self, inner: &mut Inner, ifindex: u32, has_eth_header: bool) {
        if has_eth_header != inner.has_eth_header
            && inner.tc.ingress_stages.is_empty()
            && inner.tc.egress_stages.is_empty()
        {
            let l3_offset = if has_eth_header { 14 } else { 0 };
            match Self::create_ingress_root(&self.backbone, self.id, l3_offset) {
                Ok(root) => inner.tc.ingress_root = Some(root),
                Err(err) => tracing::warn!(
                    chain = self.id, error = %err, "rebuilding TC ingress root after link change failed"
                ),
            }
        }
        match inner.ifindex {
            Some(old) if old != ifindex => {
                tracing::info!(
                    chain = self.id,
                    old_ifindex = old,
                    ifindex,
                    "wan link rebound to a new ifindex"
                );
            }
            None => tracing::debug!(chain = self.id, ifindex, "wan link bound to ifindex"),
            _ => {}
        }
        inner.ifindex = Some(ifindex);
        inner.has_eth_header = has_eth_header;
    }

    // ── stage attach entry points ──

    pub fn attach_mss(
        self: &Arc<Self>,
        ifindex: u32,
        mtu: u16,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(ifindex, has_eth_header);
        crate::stages::mss::init_mss(self, mtu, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    pub fn attach_nat4(
        self: &Arc<Self>,
        ifindex: u32,
        has_eth_header: bool,
        config: &NatConfig,
        wan_addr: Ipv4Addr,
        static_configs: &[landscape_common::config_service::static_nat::config4::RuntimeStaticNatMappingV4Config],
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(ifindex, has_eth_header);
        crate::stages::nat4::attach_nat4(
            self,
            ifindex,
            has_eth_header,
            config,
            wan_addr,
            static_configs,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
        .map_err(|e| e.to_string())
    }

    pub fn attach_nat6(
        self: &Arc<Self>,
        ifindex: u32,
        has_eth_header: bool,
        prefix: Option<(Ipv6Addr, u8)>,
        wan_addr: Option<Ipv6Addr>,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(ifindex, has_eth_header);
        crate::stages::nat6::attach_nat6(self, ifindex, has_eth_header, prefix, wan_addr)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    pub fn attach_firewall(
        self: &Arc<Self>,
        ifindex: u32,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(ifindex, has_eth_header);
        crate::stages::firewall::init_firewall(self, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    pub fn attach_pppoe_session(
        self: &Arc<Self>,
        ifindex: u32,
        tmpl: PppoeEgressTmpl,
        mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(ifindex, true);
        let handle = crate::pppoe::pppoe_handle::create_pppoe_handle(
            self.clone(),
            ifindex,
            to_bpf_tmpl(&tmpl),
            mtu,
        )
        .map_err(|e| e.to_string())?;
        // The trie is keyed by the numeric (host-order) session id;
        // `tmpl.session_id` is network byte order like every wire field.
        let session = tmpl.session_id_host();
        if self.id != 0 {
            self.backbone.trie().set_ppp_session(ifindex, session, self.id as u32);
        } else {
            tracing::warn!(ifindex, "pppoe session with unassigned chain 0; trie publish skipped");
        }
        Ok(Box::new(PppTrieGuard {
            _inner: Box::new(handle),
            wan_trie: self.backbone.trie().clone(),
            ifindex,
            session,
        }))
    }

    // ── WAN address binds ──

    pub fn bind_wan_ipv4(
        &self,
        ifindex: u32,
        addr: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        self.bind_ipv4(ifindex, addr, gateway, mask, mac, BindKind::L2);
    }

    /// A pppd-owned `pppX` is a point-to-point L3 link: no Ethernet header
    /// and no gateway MAC to resolve.
    pub fn bind_ppp_ipv4(&self, ifindex: u32, addr: Ipv4Addr, peer: Ipv4Addr, mask: u8) {
        self.bind_ipv4(ifindex, addr, Some(peer), mask, None, BindKind::Ppp);
    }

    /// Native PPPoE has an Ethernet header, but its session supplies the peer MAC.
    pub fn bind_pppoe_ipv4(&self, ifindex: u32, addr: Ipv4Addr, peer: Ipv4Addr, mac: MacAddr) {
        self.bind_ipv4(ifindex, addr, Some(peer), 32, Some(mac), BindKind::NativePppoe);
    }

    fn bind_ipv4(
        &self,
        ifindex: u32,
        addr: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
        kind: BindKind,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        inner.is_ppp = matches!(kind, BindKind::Ppp);
        self.observe_interface(&mut inner, ifindex, mac.is_some());
        maps::wan::add_ipv4_wan_ip(self.backbone.paths(), ifindex, addr, gateway, mask, mac);
        let bind = AddrBind {
            ifindex,
            addr: IpAddr::V4(addr),
            gateway: gateway.map(IpAddr::V4),
            mask,
            mac,
            is_pppoe: matches!(kind, BindKind::NativePppoe),
        };
        self.publish_bind(&bind);
        inner.v4 = Some(bind);
        self.sync_wan_binding(&mut inner);
    }

    pub fn unbind_wan_ipv4(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        if let Some(bind) = inner.v4.take() {
            maps::wan::del_ipv4_wan_ip(self.backbone.paths(), bind.ifindex);
            self.unpublish_bind(&bind);
        } else {
            tracing::debug!(chain = self.id, "unbind_wan_ipv4 without a recorded binding");
        }
        self.sync_wan_binding(&mut inner);
    }

    pub fn bind_wan_ipv6(
        &self,
        ifindex: u32,
        addr: Ipv6Addr,
        gateway: Option<Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        self.bind_ipv6(ifindex, addr, gateway, mask, mac, false);
    }

    /// Native PPPoE v6: the session supplies the peer MAC, so the IPv6
    /// gateway is never resolvable directly on the wire.
    pub fn bind_pppoe_ipv6(
        &self,
        ifindex: u32,
        addr: Ipv6Addr,
        gateway: Option<Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        self.bind_ipv6(ifindex, addr, gateway, mask, mac, true);
    }

    fn bind_ipv6(
        &self,
        ifindex: u32,
        addr: Ipv6Addr,
        gateway: Option<Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
        is_pppoe: bool,
    ) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        self.observe_interface(&mut inner, ifindex, mac.is_some());
        maps::wan::add_ipv6_wan_ip(self.backbone.paths(), ifindex, addr, gateway, mask, mac);
        let bind = AddrBind {
            ifindex,
            addr: IpAddr::V6(addr),
            gateway: gateway.map(IpAddr::V6),
            mask,
            mac,
            is_pppoe,
        };
        self.publish_bind(&bind);
        inner.v6 = Some(bind);
        self.sync_wan_binding(&mut inner);
    }

    pub fn unbind_wan_ipv6(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        if let Some(bind) = inner.v6.take() {
            maps::wan::del_ipv6_wan_ip(self.backbone.paths(), bind.ifindex);
            self.unpublish_bind(&bind);
        } else {
            tracing::debug!(chain = self.id, "unbind_wan_ipv6 without a recorded binding");
        }
        self.sync_wan_binding(&mut inner);
    }

    /// Publish the link's WAN address binding to the dispatch trie
    /// (the sole dispatch authority for the chain roots).
    fn publish_bind(&self, bind: &AddrBind) {
        if self.id == 0 {
            tracing::warn!("wan bind with unassigned chain 0; trie publish skipped");
            return;
        }
        match bind.addr {
            IpAddr::V4(addr) => {
                if let Err(e) = self.backbone.trie().set_ipv4_prefix(addr, 32, self.id as u32) {
                    tracing::warn!(chain = self.id, %addr, error = %e, "wan trie v4 publish failed");
                }
            }
            IpAddr::V6(addr) => {
                if let Err(e) =
                    self.backbone.trie().set_ipv6_prefix(addr, bind.mask, self.id as u32)
                {
                    tracing::warn!(chain = self.id, %addr, error = %e, "wan trie v6 publish failed");
                }
            }
        }
    }

    fn unpublish_bind(&self, bind: &AddrBind) {
        match bind.addr {
            IpAddr::V4(addr) => self.backbone.trie().del_ipv4_prefix(addr, 32),
            IpAddr::V6(addr) => self.backbone.trie().del_ipv6_prefix(addr, bind.mask),
        }
    }

    // ── teardown ──

    /// Tear the link's chain down: drop the recorded address bindings
    /// (unpublishing them), remove the root prog-array slots, and mark
    /// the dataplane closed — later stage operations become no-ops.
    /// Idempotent.
    pub fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return;
        }
        inner.clear_gateway_macs();
        inner.gateway_arp = GatewayArpState::default();
        if let Some(bind) = inner.v4.take() {
            maps::wan::del_ipv4_wan_ip(self.backbone.paths(), bind.ifindex);
            self.unpublish_bind(&bind);
        }
        if let Some(bind) = inner.v6.take() {
            maps::wan::del_ipv6_wan_ip(self.backbone.paths(), bind.ifindex);
            self.unpublish_bind(&bind);
        }
        if !inner.xdp.wan_stages.is_empty() || !inner.xdp.lan_stages.is_empty() {
            tracing::warn!(
                chain = self.id,
                "tearing down wan link with xdp stages still registered"
            );
        }
        if !inner.tc.ingress_stages.is_empty() || !inner.tc.egress_stages.is_empty() {
            tracing::warn!(
                chain = self.id,
                "tearing down wan link with tc stages still registered"
            );
        }
        self.backbone.unregister_xdp_roots(self.id);
        let slot = (self.id as u32).to_ne_bytes();
        if let Ok(map) = pinned_map(&self.backbone.paths().tc_pipe_root_progs_path()) {
            let _ = map.delete(&slot);
        }
        if let Ok(map) = pinned_map(&self.backbone.paths().tc_wan_egress_roots_path()) {
            let _ = map.delete(&slot);
        }
        inner.closed = true;
        tracing::info!(chain = self.id, "wan link dataplane torn down");
    }

    // ── views for the stage loaders ──

    pub(crate) fn xdp(&self) -> XdpChainView<'_> {
        XdpChainView::new(self)
    }

    pub(crate) fn tc(&self) -> TcChainView<'_> {
        TcChainView::new(self)
    }

    fn guard_open(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        if inner.closed {
            tracing::warn!(chain = self.id, "stage operation on closed wan link dataplane skipped");
            return false;
        }
        true
    }
}

/// Wraps a PPPoE dataplane guard so its dispatch-trie session entry is
/// unpublished when the session goes away.
struct PppTrieGuard {
    _inner: Box<dyn DataplaneGuard>,
    wan_trie: Arc<WanTrieDispatcher>,
    ifindex: u32,
    session: u16,
}

impl DataplaneGuard for PppTrieGuard {}

impl Drop for PppTrieGuard {
    fn drop(&mut self) {
        self.wan_trie.del_ppp_session(self.ifindex, self.session);
    }
}

impl Drop for WanLinkDataplane {
    fn drop(&mut self) {
        let closed = self.inner.lock().unwrap().closed;
        if !closed {
            tracing::warn!(
                chain = self.id,
                "wan link dataplane dropped without close(); tearing down"
            );
            self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind4(ifindex: u32) -> AddrBind {
        AddrBind {
            ifindex,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            gateway: None,
            mask: 32,
            mac: None,
            is_pppoe: false,
        }
    }

    #[test]
    fn v4_binding_is_take_once() {
        let mut inner = Inner { v4: Some(bind4(2)), ..Default::default() };
        assert!(inner.v4.take().is_some());
        assert!(inner.v4.take().is_none());
    }

    #[test]
    fn rebind_overwrites_the_previous_binding() {
        let mut inner = Inner { v4: Some(bind4(2)), ..Default::default() };
        inner.v4 = Some(bind4(3));
        assert_eq!(inner.v4.unwrap().ifindex, 3);
    }

    #[test]
    fn v4_and_v6_recordings_are_independent() {
        let mut inner = Inner {
            v4: Some(bind4(2)),
            v6: Some(AddrBind {
                ifindex: 2,
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                gateway: None,
                mask: 64,
                mac: None,
                is_pppoe: false,
            }),
            ..Default::default()
        };
        assert!(inner.v4.take().is_some());
        assert!(inner.v6.is_some());
    }
}
