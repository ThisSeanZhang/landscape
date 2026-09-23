//! Link-scoped session signal.
//!
//! Each link owns exactly one session/anchor (the v4 acquisition for ethernet
//! / native PPPoE, or the pppd session) — except a PD-only ethernet link, whose
//! "net iface present" anchor is synthesized by the link supervisor.
//!
//! The driver publishes [`SessionState`] transitions here; the link runtime
//! consumes them to (re)start or stop the sub-services that ride on the
//! session. The state carries the current lease so a mid-session address change
//! (DHCP renew, pppd peer change) is observable without a global route event.
//!
//! Delivered as a `watch` channel (not a fire-and-forget event stream) so a
//! late subscriber always reads the current state instead of missing `Ready`.
//!
//! TODO(wan-link-reapply): a datapath reset that does not produce a
//! `SessionState` transition (e.g. a future global eBPF reload) leaves the
//! already-attached sections holding stale dataplane state, because the link
//! supervisor only reacts to session transitions. Closing this needs an
//! explicit control-plane signal — a `Reapply` command or a dataplane
//! generation counter on the session signal that `reconcile` watches. This is
//! independent of how the datapath keys its state; per-link `link_id`
//! ownership would merely make such a reset notifiable per link.

use std::net::Ipv4Addr;

use tokio::sync::watch;

/// The IPv4 address the session currently holds, enough for NAT to rebind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WanV4Lease {
    pub ifindex: u32,
    pub ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

/// Lifecycle of a link's session/anchor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SessionState {
    /// No session configured, or it has been stopped.
    #[default]
    Idle,
    /// Acquiring (DHCP discover/request, PPPoE LCP/IPCP, pppd spawn).
    Starting,
    /// The net iface is usable. `lease` is `Some` when v4 acquisition is part
    /// of the link; a PPP link with no v4 intent is `Ready { lease: None }`.
    Ready { lease: Option<WanV4Lease> },
    /// Usable state was lost. `retrying` is true while the driver intends to
    /// re-establish (PPP redial / DHCP re-acquire), false on a graceful stop
    /// requested by the runtime.
    Lost { retrying: bool },
    /// Terminal failure; the driver will not retry on its own.
    Failed,
}

impl SessionState {
    pub fn is_ready(&self) -> bool {
        matches!(self, SessionState::Ready { .. })
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, SessionState::Failed | SessionState::Idle)
    }
}

/// Producer half handed to a session driver.
#[derive(Clone)]
pub struct SessionSignal {
    tx: watch::Sender<SessionState>,
}

impl Default for SessionSignal {
    fn default() -> Self {
        Self::new().0
    }
}

impl SessionSignal {
    /// Creates the signal pair: producer for the driver, receiver for the
    /// link supervisor.
    pub fn new() -> (Self, watch::Receiver<SessionState>) {
        let (tx, rx) = watch::channel(SessionState::Idle);
        (Self { tx }, rx)
    }

    /// Publishes a new state, skipping the notification when unchanged.
    pub fn set(&self, state: SessionState) {
        let _ = self.tx.send_if_modified(|current| {
            if *current == state {
                false
            } else {
                tracing::debug!(?state, "session state changed");
                *current = state;
                true
            }
        });
    }

    pub fn current(&self) -> SessionState {
        self.tx.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_skips_unchanged_state() {
        let (signal, mut rx) = SessionSignal::new();
        assert_eq!(*rx.borrow_and_update(), SessionState::Idle);

        signal.set(SessionState::Starting);
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), SessionState::Starting);

        signal.set(SessionState::Starting);
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn lease_change_is_a_distinct_state() {
        let (signal, mut rx) = SessionSignal::new();
        let first = WanV4Lease {
            ifindex: 5,
            ip: Ipv4Addr::new(192, 0, 2, 10),
            gateway: Ipv4Addr::new(192, 0, 2, 1),
        };
        let second = WanV4Lease { ip: Ipv4Addr::new(192, 0, 2, 11), ..first };

        signal.set(SessionState::Ready { lease: Some(first) });
        assert_eq!(*rx.borrow_and_update(), SessionState::Ready { lease: Some(first) });

        signal.set(SessionState::Ready { lease: Some(second) });
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), SessionState::Ready { lease: Some(second) });
    }

    #[test]
    fn ready_without_v4_lease_is_valid() {
        let (signal, rx) = SessionSignal::new();
        signal.set(SessionState::Ready { lease: None });
        assert!(rx.borrow().is_ready());
    }
}
