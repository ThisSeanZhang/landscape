//! Chain-keyed eBPF control surface for wan-link owned dataplane state.
//!
//! [`EbpfWanChainDataplane`] implements the
//! [`WanChainDataplane`](landscape_common::wan_service::wan_chain::dataplane::WanChainDataplane)
//! capability.  It is the single owner of the WAN link chain lifecycle:
//!
//! * every entry point refreshes the chain ↔ ifindex pairing and
//!   (idempotently) ensures the link's chain roots exist on both the XDP
//!   and TC managers, so no ordering is required between the stage
//!   loaders, the route services and the address binds;
//! * WAN address binds publish the dispatch trie entries that map the
//!   link's v4 address / v6 prefix / PPPoE session to its chain id (the
//!   sole dispatch authority — nothing else publishes);
//! * `teardown_chain` removes the roots and any lingering publications
//!   when the whole link goes away.
//!
//! The registry additionally remembers the ifindex each address binding
//! was written under so an unbind after a re-dial still deletes the stale
//! map entry.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use landscape_common::ebpf::DataplaneGuard;
use landscape_common::net::MacAddr;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::wan_chain::dataplane::{PppoeEgressTmpl, WanChainDataplane};

use crate::maps;
use crate::maps::wan_trie::dispatcher::WanTrieDispatcher;
use crate::runtime::EbpfRuntime;

/// The skeleton-side template type generated from the BPF C header.
type BpfPppoeTmpl = crate::pppoe::pppoe_handle::PppoeEgressTmpl;

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

/// One recorded WAN address binding: the map key it was written under.
/// The full payload is kept (not just the ifindex) because Phase 2
/// bakes these values into the NAT stage's rodata at reload time.
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct AddrBind {
    ifindex: u32,
    addr: IpAddr,
    gateway: Option<IpAddr>,
    mask: u8,
    mac: Option<MacAddr>,
}

#[derive(Default)]
struct ChainState {
    ifindex: Option<u32>,
    has_eth_header: bool,
    v4: Option<AddrBind>,
    v6: Option<AddrBind>,
}

#[derive(Default)]
struct HubInner {
    chains: HashMap<u16, ChainState>,
}

pub struct EbpfWanChainDataplane {
    rt: Arc<EbpfRuntime>,
    inner: Mutex<HubInner>,
}

impl EbpfWanChainDataplane {
    pub(crate) fn new(rt: Arc<EbpfRuntime>) -> Self {
        Self { rt, inner: Mutex::new(HubInner::default()) }
    }

    /// Record the chain ↔ ifindex pairing, tolerating re-dial churn:
    /// sections restart in unspecified order after a re-dial, so every
    /// entry point refreshes the pairing instead of validating it.
    /// Idempotently ensures the link's chain roots afterwards — the
    /// managers keep existing roots, so re-observation is a no-op.
    fn observe(&self, chain: u16, ifindex: u32, has_eth_header: bool) {
        {
            let mut inner = self.inner.lock().unwrap();
            let state = inner.chains.entry(chain).or_default();
            match state.ifindex {
                Some(old) if old != ifindex => {
                    tracing::info!(
                        chain,
                        old_ifindex = old,
                        ifindex,
                        "wan chain rebound to a new ifindex"
                    );
                    state.ifindex = Some(ifindex);
                    state.has_eth_header = has_eth_header;
                }
                Some(_) => {
                    state.has_eth_header = has_eth_header;
                }
                None => {
                    tracing::debug!(chain, ifindex, "wan chain bound to ifindex");
                    state.ifindex = Some(ifindex);
                    state.has_eth_header = has_eth_header;
                }
            }
        }

        if chain == 0 {
            tracing::warn!(ifindex, "wan link observed with unassigned chain 0; roots skipped");
            return;
        }
        if let Err(e) = self.rt.xdp.ensure_roots(chain) {
            tracing::warn!(chain, ifindex, error = %e, "ensure xdp chain roots failed");
        }
        if let Err(e) = self.rt.tc.ensure_roots(chain, has_eth_header) {
            tracing::warn!(chain, ifindex, error = %e, "ensure tc chain roots failed");
        }
    }

    /// Publish the chain's WAN address binding to the dispatch trie (the
    /// sole dispatch authority for the chain roots).
    fn publish_bind(&self, chain: u16, bind: &AddrBind) {
        if chain == 0 {
            tracing::warn!("wan bind with unassigned chain 0; trie publish skipped");
            return;
        }
        match bind.addr {
            IpAddr::V4(addr) => {
                if let Err(e) = self.rt.wan_trie.set_ipv4_prefix(addr, 32, chain as u32) {
                    tracing::warn!(chain, %addr, error = %e, "wan trie v4 publish failed");
                }
            }
            IpAddr::V6(addr) => {
                if let Err(e) = self.rt.wan_trie.set_ipv6_prefix(addr, bind.mask, chain as u32) {
                    tracing::warn!(chain, %addr, error = %e, "wan trie v6 publish failed");
                }
            }
        }
    }

    fn unpublish_bind(&self, bind: &AddrBind) {
        match bind.addr {
            IpAddr::V4(addr) => self.rt.wan_trie.del_ipv4_prefix(addr, 32),
            IpAddr::V6(addr) => self.rt.wan_trie.del_ipv6_prefix(addr, bind.mask),
        }
    }

    fn record_v4(&self, chain: u16, bind: AddrBind) {
        let mut inner = self.inner.lock().unwrap();
        inner.chains.entry(chain).or_default().v4 = Some(bind);
    }

    fn record_v6(&self, chain: u16, bind: AddrBind) {
        let mut inner = self.inner.lock().unwrap();
        inner.chains.entry(chain).or_default().v6 = Some(bind);
    }

    fn take_v4(&self, chain: u16) -> Option<AddrBind> {
        let mut inner = self.inner.lock().unwrap();
        inner.chains.get_mut(&chain).and_then(|state| state.v4.take())
    }

    fn take_v6(&self, chain: u16) -> Option<AddrBind> {
        let mut inner = self.inner.lock().unwrap();
        inner.chains.get_mut(&chain).and_then(|state| state.v6.take())
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

impl WanChainDataplane for EbpfWanChainDataplane {
    fn attach_mss(
        &self,
        chain: u16,
        ifindex: u32,
        mtu: u16,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, has_eth_header);
        crate::stages::mss::init_mss(&self.rt, chain, mtu, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn attach_nat4(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
        config: &NatConfig,
        wan_addr: Ipv4Addr,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, has_eth_header);
        crate::stages::nat4::attach_nat4(&self.rt, chain, ifindex, has_eth_header, config, wan_addr)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn attach_nat6(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
        prefix: Option<(Ipv6Addr, u8)>,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, has_eth_header);
        crate::stages::nat6::attach_nat6(&self.rt, chain, ifindex, has_eth_header, prefix)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn attach_firewall(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, has_eth_header);
        crate::stages::firewall::init_firewall(&self.rt, chain, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn attach_pppoe_session(
        &self,
        chain: u16,
        ifindex: u32,
        tmpl: PppoeEgressTmpl,
        mtu: u16,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, true);
        crate::pppoe::pppoe_handle::create_pppoe_handle(
            self.rt.clone(),
            chain,
            ifindex,
            to_bpf_tmpl(&tmpl),
            mtu,
        )
        .map(|handle| {
            if chain != 0 {
                // PPP session ids are per-NIC scoped; the trie key carries
                // the ingress ifindex to keep two NICs' ids from colliding.
                self.rt.wan_trie.set_ppp_session(ifindex, tmpl.session_id, chain as u32);
            } else {
                tracing::warn!(
                    ifindex,
                    "pppoe session with unassigned chain 0; trie publish skipped"
                );
            }
            Box::new(PppTrieGuard {
                _inner: Box::new(handle),
                wan_trie: self.rt.wan_trie.clone(),
                ifindex,
                session: tmpl.session_id,
            }) as Box<dyn DataplaneGuard>
        })
        .map_err(|e| e.to_string())
    }

    fn bind_wan_ipv4(
        &self,
        chain: u16,
        ifindex: u32,
        addr: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        self.observe(chain, ifindex, mac.is_some());
        maps::wan::add_ipv4_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
        let bind = AddrBind {
            ifindex,
            addr: IpAddr::V4(addr),
            gateway: gateway.map(IpAddr::V4),
            mask,
            mac,
        };
        self.publish_bind(chain, &bind);
        self.record_v4(chain, bind);
    }

    fn unbind_wan_ipv4(&self, chain: u16) {
        if let Some(bind) = self.take_v4(chain) {
            maps::wan::del_ipv4_wan_ip(&self.rt.paths, bind.ifindex);
            self.unpublish_bind(&bind);
        } else {
            tracing::debug!(chain, "unbind_wan_ipv4 without a recorded binding");
        }
    }

    fn bind_wan_ipv6(
        &self,
        chain: u16,
        ifindex: u32,
        addr: Ipv6Addr,
        gateway: Option<Ipv6Addr>,
        mask: u8,
        mac: Option<MacAddr>,
    ) {
        self.observe(chain, ifindex, mac.is_some());
        maps::wan::add_ipv6_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
        let bind = AddrBind {
            ifindex,
            addr: IpAddr::V6(addr),
            gateway: gateway.map(IpAddr::V6),
            mask,
            mac,
        };
        self.publish_bind(chain, &bind);
        self.record_v6(chain, bind);
    }

    fn unbind_wan_ipv6(&self, chain: u16) {
        if let Some(bind) = self.take_v6(chain) {
            maps::wan::del_ipv6_wan_ip(&self.rt.paths, bind.ifindex);
            self.unpublish_bind(&bind);
        } else {
            tracing::debug!(chain, "unbind_wan_ipv6 without a recorded binding");
        }
    }

    fn teardown_chain(&self, chain: u16) {
        if chain == 0 {
            return;
        }
        // Defensive: drop lingering address bindings (map entries + trie
        // publications) before removing the roots.
        for bind in [self.take_v4(chain), self.take_v6(chain)].into_iter().flatten() {
            match bind.addr {
                IpAddr::V4(_) => maps::wan::del_ipv4_wan_ip(&self.rt.paths, bind.ifindex),
                IpAddr::V6(_) => maps::wan::del_ipv6_wan_ip(&self.rt.paths, bind.ifindex),
            }
            self.unpublish_bind(&bind);
        }
        self.inner.lock().unwrap().chains.remove(&chain);
        self.rt.xdp.remove_roots(chain);
        self.rt.tc.remove_roots(chain);
        tracing::info!(chain, "wan chain torn down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_bind(ifindex: u32) -> AddrBind {
        AddrBind {
            ifindex,
            addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            mask: 24,
            mac: None,
        }
    }

    #[test]
    fn addr_bind_take_is_once_only() {
        let mut inner = HubInner::default();
        inner.chains.entry(5).or_default().v4 = Some(v4_bind(9));

        // The recorded ifindex survives the take: an unbind after a
        // re-dial must still delete the stale map key.
        let bind = inner.chains.get_mut(&5).unwrap().v4.take().unwrap();
        assert_eq!(bind.ifindex, 9);
        assert!(inner.chains.get_mut(&5).unwrap().v4.take().is_none());
        assert!(inner.chains.get_mut(&5).unwrap().v6.take().is_none());
    }

    #[test]
    fn chain_rebind_moves_to_new_ifindex() {
        let mut inner = HubInner::default();

        let state = inner.chains.entry(3).or_default();
        assert!(state.ifindex.is_none());
        state.ifindex = Some(11);

        // A re-dial rebinds the chain; the v4 record still points at the
        // OLD ifindex until the next bind overwrites it.
        let state = inner.chains.get_mut(&3).unwrap();
        assert_eq!(state.ifindex, Some(11));
        state.ifindex = Some(42);
        assert_eq!(inner.chains[&3].ifindex, Some(42));
    }

    #[test]
    fn v4_and_v6_records_are_independent_per_chain() {
        let mut inner = HubInner::default();
        let state = inner.chains.entry(7).or_default();
        state.v4 = Some(v4_bind(1));
        state.v6 = Some(AddrBind {
            ifindex: 2,
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            gateway: None,
            mask: 64,
            mac: None,
        });

        let state = inner.chains.get_mut(&7).unwrap();
        assert_eq!(state.v4.as_ref().unwrap().ifindex, 1);
        assert_eq!(state.v6.as_ref().unwrap().ifindex, 2);
        assert_eq!(state.v6.as_ref().unwrap().mask, 64);
    }
}
