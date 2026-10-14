//! Chain-keyed eBPF control surface for wan-link owned dataplane state.
//!
//! [`EbpfWanChainDataplane`] implements the
//! [`WanChainDataplane`](landscape_common::wan_service::wan_chain::dataplane::WanChainDataplane)
//! capability: it delegates stage attaches to the existing `stages::*`
//! loaders and WAN address binds to the `wan_ip_binding` map writers
//! (both still ifindex-scoped), while maintaining a registry keyed by
//! the link's immutable chain id:
//!
//! * the chain ↔ ifindex pairing, updated (and logged) whenever a
//!   re-dial moves the link to a new ifindex;
//! * the chain's current WAN address bindings, remembering the ifindex
//!   each binding was written under so an unbind after a re-dial still
//!   deletes the stale map entry.
//!
//! The independent per-iface route services keep attaching the chain
//! roots through the managers directly; this hub only adds the
//! chain-level bookkeeping on top.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use landscape_common::ebpf::DataplaneGuard;
use landscape_common::net::MacAddr;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::wan_chain::dataplane::{PppoeEgressTmpl, WanChainDataplane};

use crate::maps;
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
    fn observe(&self, chain: u16, ifindex: u32, has_eth_header: bool) {
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

impl WanChainDataplane for EbpfWanChainDataplane {
    fn attach_mss(
        &self,
        chain: u16,
        ifindex: u32,
        mtu: u16,
        has_eth_header: bool,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, has_eth_header);
        crate::stages::mss::init_mss(&self.rt, ifindex, mtu, has_eth_header)
            .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
            .map_err(|e| e.to_string())
    }

    fn attach_nat(
        &self,
        chain: u16,
        ifindex: u32,
        has_eth_header: bool,
        config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        self.observe(chain, ifindex, has_eth_header);
        crate::stages::nat::init_nat(&self.rt, ifindex, has_eth_header, config)
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
        crate::stages::firewall::init_firewall(&self.rt, ifindex, has_eth_header)
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
            ifindex,
            to_bpf_tmpl(&tmpl),
            mtu,
        )
        .map(|handle| Box::new(handle) as Box<dyn DataplaneGuard>)
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
        maps::wan::add_ipv4_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
        self.record_v4(
            chain,
            AddrBind {
                ifindex,
                addr: IpAddr::V4(addr),
                gateway: gateway.map(IpAddr::V4),
                mask,
                mac,
            },
        );
    }

    fn unbind_wan_ipv4(&self, chain: u16) {
        if let Some(bind) = self.take_v4(chain) {
            maps::wan::del_ipv4_wan_ip(&self.rt.paths, bind.ifindex);
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
        maps::wan::add_ipv6_wan_ip(&self.rt.paths, ifindex, addr, gateway, mask, mac);
        self.record_v6(
            chain,
            AddrBind {
                ifindex,
                addr: IpAddr::V6(addr),
                gateway: gateway.map(IpAddr::V6),
                mask,
                mac,
            },
        );
    }

    fn unbind_wan_ipv6(&self, chain: u16) {
        if let Some(bind) = self.take_v6(chain) {
            maps::wan::del_ipv6_wan_ip(&self.rt.paths, bind.ifindex);
        } else {
            tracing::debug!(chain, "unbind_wan_ipv6 without a recorded binding");
        }
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
