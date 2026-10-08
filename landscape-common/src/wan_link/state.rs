//! Per-link runtime rendezvous between the v4 acquisition section and the
//! dependent sections (nat / mss / firewall / pd). This is *not* a lifecycle
//! status: the environment task is the only writer of `carrier`, the v4
//! section the only writer of `session`. Readers gate startup on it and
//! re-attach when the session is rebuilt (PPP redial, DHCP rebind, IP
//! change).

use std::net::IpAddr;

use tokio::sync::watch;

use crate::dev::LandscapeInterface;
use crate::net::MacAddr;

/// The iface the dependent sections operate on once a session is up: the
/// attach iface for ethernet / native PPPoE, the ppp device for pppd.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionIface {
    pub ifindex: u32,
    pub iface_name: String,
    pub mac: Option<MacAddr>,
    pub ip: Option<IpAddr>,
}

impl SessionIface {
    pub fn new(ifindex: u32, iface_name: impl Into<String>, mac: Option<MacAddr>) -> Self {
        Self {
            ifindex,
            iface_name: iface_name.into(),
            mac,
            ip: None,
        }
    }

    pub fn with_ip(mut self, ip: Option<IpAddr>) -> Self {
        self.ip = ip;
        self
    }

    pub fn has_mac(&self) -> bool {
        self.mac.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum SessionPhase {
    #[default]
    Down,
    Up(SessionIface),
}

impl SessionPhase {
    pub fn is_up(&self) -> bool {
        matches!(self, SessionPhase::Up(_))
    }

    pub fn iface(&self) -> Option<&SessionIface> {
        match self {
            SessionPhase::Down => None,
            SessionPhase::Up(iface) => Some(iface),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SessionState {
    pub phase: SessionPhase,
    /// Bumped on every (re)acquisition; a change means dependents re-attach.
    pub epoch: u64,
}

impl SessionState {
    pub fn is_up(&self) -> bool {
        self.phase.is_up()
    }
}

#[derive(Debug, Clone, Default)]
pub struct LinkState {
    /// Physical attach interface; `None` while the carrier is down.
    pub carrier: Option<LandscapeInterface>,
    pub session: SessionState,
}

/// Writer/reader handle for a link's [`LinkState`].
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

    /// Environment task: reflect carrier presence (attach iface up/down).
    pub fn set_carrier(&self, carrier: Option<LandscapeInterface>) {
        self.tx.send_modify(|state| state.carrier = carrier);
    }

    /// v4 section: session (re)established; bumps the epoch only on change.
    pub fn session_up(&self, iface: SessionIface) {
        self.tx.send_modify(|state| {
            let new_phase = SessionPhase::Up(iface);
            if state.session.phase == new_phase {
                return;
            }
            state.session.phase = new_phase;
            state.session.epoch = state.session.epoch.wrapping_add(1);
        });
    }

    /// v4 section: session gone. Idempotent.
    pub fn session_down(&self) {
        self.tx.send_modify(|state| {
            if !state.session.phase.is_up() {
                return;
            }
            state.session.phase = SessionPhase::Down;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn iface(ip: Option<IpAddr>) -> SessionIface {
        SessionIface::new(3, "eth0", None).with_ip(ip)
    }

    #[test]
    fn session_up_bumps_epoch_only_on_change() {
        let (handle, rx) = LinkStateHandle::new(None);
        assert_eq!(rx.borrow().session.epoch, 0);
        assert!(!rx.borrow().session.is_up());

        handle.session_up(iface(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))));
        assert_eq!(rx.borrow().session.epoch, 1);

        handle.session_up(iface(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))));
        assert_eq!(rx.borrow().session.epoch, 1);

        handle.session_up(iface(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))));
        assert_eq!(rx.borrow().session.epoch, 2);

        handle.session_down();
        handle.session_down();
        assert!(!rx.borrow().session.is_up());
        assert_eq!(rx.borrow().session.epoch, 2);
        handle.session_up(iface(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))));
        assert_eq!(rx.borrow().session.epoch, 3);
    }

    #[test]
    fn session_up_does_not_require_carrier() {
        let (handle, rx) = LinkStateHandle::new(None);
        handle.session_up(iface(None));
        let snapshot = rx.borrow().clone();
        assert!(snapshot.session.is_up());
        assert!(snapshot.carrier.is_none());
        handle.set_carrier(None);
        assert!(rx.borrow().carrier.is_none());
    }
}
