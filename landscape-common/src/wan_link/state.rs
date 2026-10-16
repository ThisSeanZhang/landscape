//! Per-link rendezvous between the v4 acquisition section and the dependent
//! sections (nat / mss / firewall / pd): physical carrier + current session.
//! The v4 section writes `session`; the link environment task writes `carrier`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::watch;

use crate::dev::LandscapeInterface;
use crate::net::MacAddr;

/// The net interface a link's sections operate on: the attach iface for
/// ethernet / native PPPoE, the ppp device for pppd.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionIface {
    pub ifindex: u32,
    pub iface_name: String,
    pub mac: Option<MacAddr>,
    /// IPv6CP link-local (native PPPoE): the session's stable DHCPv6
    /// source address (chain steering is the HostDirect SO_MARK).
    /// `None` without IPv6CP (ethernet WAN, pppd).
    pub v6_linklocal: Option<Ipv6Addr>,
}

impl SessionIface {
    pub fn new(ifindex: u32, iface_name: impl Into<String>, mac: Option<MacAddr>) -> Self {
        Self {
            ifindex,
            iface_name: iface_name.into(),
            mac,
            v6_linklocal: None,
        }
    }

    pub fn with_v6_linklocal(mut self, addr: Option<Ipv6Addr>) -> Self {
        self.v6_linklocal = addr;
        self
    }

    /// Whether packets on this session iface carry a 14-byte Ethernet
    /// header before the L3 payload.  PPP (pppd) session ifaces are L3-only
    /// and therefore expose `mac == None`; ethernet / native-PPPoE anchors
    /// own a MAC and are L2-framed.
    pub fn has_eth_header(&self) -> bool {
        self.mac.is_some()
    }
}

/// The v4 lease a session holds. NAT requires its presence and re-attaches when
/// it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WanV4Lease {
    pub ifindex: u32,
    pub ip: Ipv4Addr,
}

impl WanV4Lease {
    pub fn new(ifindex: u32, ip: Ipv4Addr) -> Self {
        Self { ifindex, ip }
    }
}

/// The delegated v6 prefix the PD section bound to the WAN side. nat6 keys
/// its startup on its presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WanV6Prefix {
    pub prefix_ip: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum SessionPhase {
    #[default]
    Down,
    /// `lease` is `Some` for v4 acquisition; a PPP / PD-only anchor is `None`.
    Up { iface: SessionIface, lease: Option<WanV4Lease> },
}

impl SessionPhase {
    pub fn is_up(&self) -> bool {
        matches!(self, SessionPhase::Up { .. })
    }

    pub fn iface(&self) -> Option<&SessionIface> {
        match self {
            SessionPhase::Down => None,
            SessionPhase::Up { iface, .. } => Some(iface),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SessionState {
    pub phase: SessionPhase,
    /// The WAN v6 prefix currently bound by the PD section. Tracked outside
    /// `phase` on purpose: prefix bind / unbind must not bump `epoch`, or the
    /// pd section itself would restart on every renewal. `session_up` /
    /// `session_down` clear it so a stale prefix never survives a re-anchor.
    pub v6_prefix: Option<WanV6Prefix>,
    /// Bumped only on anchor re-index (`Up(A)` → `Up(B)`); a change tells
    /// anchor-keyed dependents (mss / firewall / pd / nat6) to re-attach.
    /// Lease changes deliberately leave it alone — see `session_up`.
    pub epoch: u64,
}

impl SessionState {
    pub fn is_up(&self) -> bool {
        self.phase.is_up()
    }

    pub fn iface(&self) -> Option<&SessionIface> {
        self.phase.iface()
    }

    pub fn has_v4_lease(&self) -> bool {
        matches!(self.phase, SessionPhase::Up { lease: Some(_), .. })
    }

    pub fn has_v6_prefix(&self) -> bool {
        self.v6_prefix.is_some()
    }

    pub fn v4_ip(&self) -> Option<IpAddr> {
        match &self.phase {
            SessionPhase::Up { lease: Some(lease), .. } => Some(IpAddr::V4(lease.ip)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinkState {
    /// Physical attach interface; `None` while it is absent.
    pub carrier: Option<LandscapeInterface>,
    pub session: SessionState,
}

#[derive(Clone)]
pub struct LinkStateHandle {
    tx: watch::Sender<LinkState>,
}

impl LinkStateHandle {
    pub fn new(carrier: Option<LandscapeInterface>) -> (Self, watch::Receiver<LinkState>) {
        let (tx, rx) = watch::channel(LinkState { carrier, session: SessionState::default() });
        (Self { tx }, rx)
    }

    pub fn subscribe(&self) -> watch::Receiver<LinkState> {
        self.tx.subscribe()
    }

    pub fn snapshot(&self) -> LinkState {
        self.tx.borrow().clone()
    }

    /// Notifies only when the (name, ifindex) identity changes, so a reindex
    /// (device reload / replug) propagates but a same-iface re-report is a no-op.
    pub fn set_carrier(&self, carrier: Option<LandscapeInterface>) {
        self.tx.send_if_modified(|state| {
            let changed = match (&state.carrier, &carrier) {
                (None, None) => false,
                (Some(old), Some(new)) => old.index != new.index || old.name != new.name,
                _ => true,
            };
            if changed {
                state.carrier = carrier;
            }
            changed
        });
    }

    /// Publishes a session anchor. `epoch` is the anchor-identity
    /// generation: it bumps only on a re-anchor — `Up(iface A)` becoming
    /// `Up(iface B)` without passing `Down` (e.g. a ppp device swap) —
    /// which is the only session change that survives no `Down` state.
    /// Transitions through `Down` propagate via `!is_up()` instead, and a
    /// lease-only change on the same anchor keeps both the generation and
    /// the bound v6 prefix stable: lease-sensitive sections (nat4 / health
    /// check) restart through their `SessionAndLease` scope, everything
    /// else keeps running.
    pub fn session_up(&self, iface: SessionIface, lease: Option<WanV4Lease>) {
        self.tx.send_if_modified(|state| {
            let reanchor = match &state.session.phase {
                SessionPhase::Up { iface: old_iface, .. } => old_iface != &iface,
                SessionPhase::Down => false,
            };
            let new_phase = SessionPhase::Up { iface, lease };
            if state.session.phase == new_phase {
                return false;
            }
            state.session.phase = new_phase;
            if reanchor {
                state.session.epoch = state.session.epoch.wrapping_add(1);
                // A new anchor invalidates any v6 prefix the pd section
                // bound on the previous one; pd restarts and re-binds.
                state.session.v6_prefix = None;
            }
            true
        });
    }

    pub fn session_down(&self) {
        self.tx.send_if_modified(|state| {
            if !state.session.phase.is_up() {
                return false;
            }
            state.session.phase = SessionPhase::Down;
            state.session.v6_prefix = None;
            true
        });
    }

    /// Publishes the WAN v6 prefix bound by the pd section. Does not bump
    /// `epoch`: the pd section must not restart on its own bind, and a
    /// same-prefix renewal is deduplicated into a no-op.
    pub fn set_v6_prefix(&self, prefix: WanV6Prefix) {
        self.tx.send_if_modified(|state| {
            if state.session.v6_prefix == Some(prefix) {
                return false;
            }
            state.session.v6_prefix = Some(prefix);
            true
        });
    }

    pub fn clear_v6_prefix(&self) {
        self.tx.send_if_modified(|state| {
            if state.session.v6_prefix.is_none() {
                return false;
            }
            state.session.v6_prefix = None;
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface() -> SessionIface {
        SessionIface::new(3, "eth0", None)
    }

    fn lease(ip: [u8; 4]) -> WanV4Lease {
        WanV4Lease::new(3, Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
    }

    #[test]
    fn epoch_tracks_anchor_identity_not_lease() {
        let (handle, rx) = LinkStateHandle::new(None);
        assert_eq!(rx.borrow().session.epoch, 0);
        assert!(!rx.borrow().session.is_up());

        // Down -> Up: no bump; the transition propagates via `!is_up()`.
        handle.session_up(iface(), Some(lease([10, 0, 0, 2])));
        assert_eq!(rx.borrow().session.epoch, 0);
        assert!(rx.borrow().session.has_v4_lease());

        // Same-value dedup is a no-op.
        handle.session_up(iface(), Some(lease([10, 0, 0, 2])));
        assert_eq!(rx.borrow().session.epoch, 0);

        // Lease change on the same anchor: no bump.
        handle.session_up(iface(), Some(lease([10, 0, 0, 3])));
        assert_eq!(rx.borrow().session.epoch, 0);
        assert!(rx.borrow().session.has_v4_lease());

        // Down -> Up again: still no bump.
        handle.session_down();
        handle.session_up(iface(), Some(lease([10, 0, 0, 3])));
        assert_eq!(rx.borrow().session.epoch, 0);

        // Re-anchor (Up -> Up with a different iface): bump.
        let other = SessionIface::new(7, "eth1", None);
        handle.session_up(other, Some(WanV4Lease::new(7, Ipv4Addr::new(10, 0, 0, 4))));
        assert_eq!(rx.borrow().session.epoch, 1);
    }

    #[test]
    fn up_without_lease_is_not_a_lease() {
        let (handle, rx) = LinkStateHandle::new(None);
        handle.session_up(iface(), None);
        let snapshot = rx.borrow().clone();
        assert!(snapshot.session.is_up());
        assert!(!snapshot.session.has_v4_lease());
        assert_eq!(snapshot.session.v4_ip(), None);
        assert!(snapshot.carrier.is_none());
    }

    fn v6_prefix(n: u16) -> WanV6Prefix {
        WanV6Prefix {
            prefix_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, n, 0, 0, 0, 0),
            prefix_len: 56,
        }
    }

    #[test]
    fn v6_prefix_updates_do_not_bump_epoch() {
        let (handle, rx) = LinkStateHandle::new(None);
        handle.session_up(iface(), None);
        let epoch = rx.borrow().session.epoch;

        handle.set_v6_prefix(v6_prefix(1));
        assert!(rx.borrow().session.has_v6_prefix());
        assert_eq!(rx.borrow().session.epoch, epoch);

        // Same-prefix renewal is a no-op (no watch notification).
        handle.set_v6_prefix(v6_prefix(1));
        assert_eq!(rx.borrow().session.epoch, epoch);

        handle.set_v6_prefix(v6_prefix(2));
        assert_eq!(rx.borrow().session.v6_prefix, Some(v6_prefix(2)));
        assert_eq!(rx.borrow().session.epoch, epoch);

        handle.clear_v6_prefix();
        assert!(!rx.borrow().session.has_v6_prefix());
        handle.clear_v6_prefix();
        assert_eq!(rx.borrow().session.epoch, epoch);
    }

    #[test]
    fn session_transitions_clear_v6_prefix() {
        let (handle, rx) = LinkStateHandle::new(None);
        handle.session_up(iface(), None);
        handle.set_v6_prefix(v6_prefix(1));

        // Lease-only change on the same anchor keeps the prefix: the pd
        // section bound it on this anchor and keeps running.
        handle.session_up(iface(), Some(lease([10, 0, 0, 2])));
        assert_eq!(rx.borrow().session.v6_prefix, Some(v6_prefix(1)));

        // Re-anchor (epoch bump) drops the stale prefix.
        let other = SessionIface::new(7, "eth1", None);
        handle.session_up(other, None);
        assert!(!rx.borrow().session.has_v6_prefix());

        handle.set_v6_prefix(v6_prefix(2));
        handle.session_down();
        assert!(!rx.borrow().session.has_v6_prefix());
    }
}
