//! Publish a WAN's egress binding to its TC egress and XDP LAN roots.

use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::{MapCore, MapFlags};

use super::{Inner, WanLinkDataplane};
use crate::bpf_error::LdEbpfResult;
use crate::route_backbone::pinned_map;

/// The WAN interface and its bound IPv4 address, prefix, source MAC and upstream gateway.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct WanEgressBinding {
    pub ifindex: u32,
    pub has_l2: bool,
    pub has_ipv4: bool,
    pub wan_ip4: u32,
    pub wan_mask4: u32,
    pub gateway_ip4: u32,
    pub source_mac: [u8; 6],
}

impl WanEgressBinding {
    fn from_link(inner: &Inner) -> Self {
        let mut binding = Self {
            ifindex: inner.ifindex.unwrap_or_default(),
            has_l2: inner.has_eth_header,
            ..Self::default()
        };
        // A hotplug observation can precede the new interface's address bind.
        if let Some(bind) = inner.v4
            && Some(bind.ifindex) == inner.ifindex
            && let IpAddr::V4(ip) = bind.addr
        {
            binding.has_ipv4 = true;
            binding.wan_ip4 = ip.to_bits().to_be();
            let prefix = bind.mask.min(32);
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            binding.wan_mask4 = mask.to_be();
            if let Some(IpAddr::V4(gateway)) = bind.gateway {
                binding.gateway_ip4 = gateway.to_bits().to_be();
            }
            binding.source_mac = bind.mac.map(|mac| mac.octets()).unwrap_or_default();
        }
        binding
    }
}

impl WanLinkDataplane {
    pub(super) fn refresh_from_lan_roots(&self, inner: &mut Inner) -> LdEbpfResult<()> {
        let binding = WanEgressBinding::from_link(inner);
        if inner.published_egress_binding == Some(binding) {
            return Ok(());
        }

        // Each replacement reuses its predecessor's next-stage map. This keeps
        // both family chains wired even for packets already running in an old root.
        let old_xdp = inner.xdp.lan_root.as_ref();
        let xdp = Self::build_lan_root(&self.backbone, self.id, &binding, old_xdp)?;
        let tc = Self::build_egress_root(&self.backbone, &binding, inner.tc.egress_root.as_ref())?;

        let tc_slots = pinned_map(&self.backbone.paths().tc_wan_egress_roots_path())?;
        let slot = u32::from(self.id).to_ne_bytes();
        let tc_fd = tc.skel.progs.tc_wan_egress_root.as_fd().as_raw_fd().to_ne_bytes();
        self.backbone
            .register_xdp_lan_root(self.id, xdp.skel.progs.xdp_lan_root.as_fd().as_raw_fd())?;
        if let Err(err) = tc_slots.update(&slot, &tc_fd, MapFlags::ANY) {
            // The two dispatch arrays are updated separately. Keep both old roots
            // alive until success. On first load, new()'s error path cleans the slots.
            if let Some(old) = old_xdp {
                let old_fd = old.skel.progs.xdp_lan_root.as_fd().as_raw_fd();
                if let Err(rollback_err) = self.backbone.register_xdp_lan_root(self.id, old_fd) {
                    inner.published_egress_binding = None;
                    tracing::error!(chain = self.id, %err, %rollback_err, "restoring XDP root failed");
                    return Err(rollback_err);
                }
            }
            return Err(err.into());
        }
        inner.xdp.lan_root = Some(xdp);
        inner.tc.egress_root = Some(tc);
        inner.published_egress_binding = Some(binding);
        Ok(())
    }

    pub(super) fn sync_from_lan_roots(&self, inner: &mut Inner) {
        if let Err(err) = self.refresh_from_lan_roots(inner) {
            tracing::warn!(chain = self.id, error = %err, "refreshing from-LAN roots failed");
        }
    }
}

#[cfg(all(test, feature = "test-chain"))]
mod tests;
