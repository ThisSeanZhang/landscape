//! Per-link rendezvous between the v4 acquisition section and the dependent
//! sections (nat / mss / firewall / pd): physical carrier + current session.
//! The v4 section writes `session`; the link environment task writes `carrier`.

use std::net::{IpAddr, Ipv4Addr};

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
}

impl SessionIface {
    pub fn new(ifindex: u32, iface_name: impl Into<String>, mac: Option<MacAddr>) -> Self {
        Self { ifindex, iface_name: iface_name.into(), mac }
    }

    pub fn has_mac(&self) -> bool {
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
    /// Bumped on (re)acquisition; a change tells dependents to re-attach.
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

    pub fn session_up(&self, iface: SessionIface, lease: Option<WanV4Lease>) {
        self.tx.send_if_modified(|state| {
            let new_phase = SessionPhase::Up { iface, lease };
            if state.session.phase == new_phase {
                return false;
            }
            state.session.phase = new_phase;
            state.session.epoch = state.session.epoch.wrapping_add(1);
            true
        });
    }

    pub fn session_down(&self) {
        self.tx.send_if_modified(|state| {
            if !state.session.phase.is_up() {
                return false;
            }
            state.session.phase = SessionPhase::Down;
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
    fn session_up_bumps_epoch_only_on_change() {
        let (handle, rx) = LinkStateHandle::new(None);
        assert_eq!(rx.borrow().session.epoch, 0);
        assert!(!rx.borrow().session.is_up());

        handle.session_up(iface(), Some(lease([10, 0, 0, 2])));
        assert_eq!(rx.borrow().session.epoch, 1);
        assert!(rx.borrow().session.has_v4_lease());

        handle.session_up(iface(), Some(lease([10, 0, 0, 2])));
        assert_eq!(rx.borrow().session.epoch, 1);

        handle.session_up(iface(), Some(lease([10, 0, 0, 3])));
        assert_eq!(rx.borrow().session.epoch, 2);

        handle.session_down();
        handle.session_down();
        assert!(!rx.borrow().session.is_up());
        assert_eq!(rx.borrow().session.epoch, 2);
        handle.session_up(iface(), Some(lease([10, 0, 0, 3])));
        assert_eq!(rx.borrow().session.epoch, 3);
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
}
