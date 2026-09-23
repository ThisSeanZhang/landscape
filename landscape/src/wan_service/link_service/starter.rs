//! Per-link runtime instance.
//!
//! One instance task exists per active `wan_links` row. It owns the link's
//! session/anchor and its sub-services and reconciles them against two inputs:
//!
//! 1. the desired config (updated in place through a channel, so an edit only
//!    restarts the parts that actually changed — it never redials PPP for an
//!    unrelated section toggle), and
//! 2. the session state published by the session driver (`SessionSignal`).
//!
//! Section lifecycle is gated on the session:
//! - `Ready` -> start the desired sections (NAT additionally needs a v4 lease)
//! - `Ready` with a changed lease -> re-attach NAT only
//! - `Lost` / `Failed` / `Idle` -> stop the sections
//!
//! Stop (link deletion or manager shutdown) tears down in reverse order:
//! sections first, then the session.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::concurrency::task_label;
use landscape_common::dev::LandscapeInterface;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::link::session::{SessionSignal, SessionState, WanV4Lease};
use landscape_common::wan_service::link::{
    LinkState, LinkStatus, WanLinkConfig, WanLinkKindConfig, WanV4Config,
};
use landscape_common::wan_service::nat::config::NatConfig;
use tokio::sync::{mpsc, watch, RwLock};

use super::drivers::{IfaceLookup, PdSpec, SectionRunner, SectionTask, SessionDriver};
use super::resolve::{resolve_mss_clamp, resolve_nat, resolve_session_spec, DEFAULT_PD_LEN};

/// Shared per-link status registry keyed by link UUID (REST reads this).
pub type LinkStatusStore = Arc<RwLock<HashMap<String, LinkStatus>>>;

/// Everything a link instance needs, with the drivers injectable for tests.
pub struct WanLinkDeps {
    pub iface_lookup: Arc<dyn IfaceLookup>,
    pub session_driver: Arc<dyn SessionDriver>,
    pub section_runner: Arc<dyn SectionRunner>,
    pub status_store: LinkStatusStore,
    /// Shared PD prefix map, also read by the manager's status endpoints.
    pub prefix_map: landscape_common::wan_service::ipv6_pd::IAPrefixMap,
}

struct ActiveSession {
    status: WatchService,
    rx: watch::Receiver<SessionState>,
    key: SessionKey,
}

/// Identity of the session work. A config edit that leaves this unchanged must
/// not touch the running session.
///
/// The attach iface is part of the identity because the session driver binds to
/// a concrete device (index), so moving a link to another iface must
/// re-establish the session. PD toggles are deliberately *not* part of the key:
/// PD is a section that rides on the session, not a session input — including it
/// would needlessly redial on every PD toggle.
#[derive(PartialEq, Clone)]
struct SessionKey {
    attach_iface_name: String,
    attach_ifindex: u32,
    kind: WanLinkKindConfig,
    v4: WanV4Config,
}

impl SessionKey {
    fn from(config: &WanLinkConfig, attach: &LandscapeInterface) -> Self {
        Self {
            attach_iface_name: attach.name.clone(),
            attach_ifindex: attach.index,
            kind: config.kind.clone(),
            v4: config.v4.clone(),
        }
    }
}

#[derive(Default)]
struct SectionChildren {
    pd: Option<(WatchService, PdSpec)>,
    nat: Option<(WatchService, NatConfig)>,
    firewall: Option<WatchService>,
    mss: Option<(WatchService, u16)>,
}

impl SectionChildren {
    async fn stop_all(&mut self) {
        if let Some((status, _)) = self.pd.take() {
            status.wait_stop().await;
        }
        if let Some((status, _)) = self.nat.take() {
            status.wait_stop().await;
        }
        if let Some(status) = self.firewall.take() {
            status.wait_stop().await;
        }
        if let Some((status, _)) = self.mss.take() {
            status.wait_stop().await;
        }
    }

    fn statuses(&self) -> (ServiceStatus, ServiceStatus, ServiceStatus, ServiceStatus) {
        let session_status =
            |slot: Option<&WatchService>| slot.map(|s| s.current()).unwrap_or(ServiceStatus::Stop);
        (
            session_status(self.pd.as_ref().map(|(s, _)| s)),
            session_status(self.nat.as_ref().map(|(s, _)| s)),
            session_status(self.firewall.as_ref()),
            session_status(self.mss.as_ref().map(|(s, _)| s)),
        )
    }
}

/// Stops any running child regardless of the key it was started with.
async fn stop_any(slot: &mut Option<WatchService>) {
    if let Some(status) = slot.take() {
        status.wait_stop().await;
    }
}

/// Runs one link instance until `status` is stopped or the manager drops the
/// config sender.
pub async fn run_link_instance(
    mut config: WanLinkConfig,
    status: WatchService,
    mut config_rx: mpsc::Receiver<WanLinkConfig>,
    deps: Arc<WanLinkDeps>,
) {
    let key = config.id.to_string();

    status.just_change_status(ServiceStatus::Staring);

    let mut children = SectionChildren::default();
    let mut session: Option<ActiveSession> = None;
    let mut last_nat_lease: Option<WanV4Lease> = None;

    let mut attach = deps.iface_lookup.get(&config.attach_iface_name).await;
    ensure_session(&config, attach.as_ref(), &deps, &mut session).await;
    reconcile(&config, &mut session, attach.as_ref(), &deps, &mut children, &mut last_nat_lease)
        .await;
    publish_status(&config, &status, session.as_ref(), &children, &deps.status_store).await;

    // Keep a receiver alive even when no session exists, so the select arm can
    // always await a change without juggling an Option across awaits.
    let (dummy_tx, dummy_rx) = watch::channel(SessionState::Idle);
    let _dummy_tx = dummy_tx;
    // Synced receiver: a raw `s.rx.clone()` would fire `changed()` forever
    // because the stored receiver's version is never advanced.
    let mut session_rx = current_session_rx(&session, &dummy_rx);

    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        let mut changed_rx = session_rx.clone();

        tokio::select! {
            _ = status.wait_to_stopping() => break,
            maybe = config_rx.recv() => {
                match maybe {
                    Some(new_config) => config = new_config,
                    None => break,
                }
                attach = deps.iface_lookup.get(&config.attach_iface_name).await;
                ensure_session(&config, attach.as_ref(), &deps, &mut session).await;
                reconcile(
                    &config,
                    &mut session,
                    attach.as_ref(),
                    &deps,
                    &mut children,
                    &mut last_nat_lease,
                )
                .await;
                publish_status(&config, &status, session.as_ref(), &children, &deps.status_store).await;
                session_rx = current_session_rx(&session, &dummy_rx);
            }
            _ = changed_rx.changed() => {
                reconcile(
                    &config,
                    &mut session,
                    attach.as_ref(),
                    &deps,
                    &mut children,
                    &mut last_nat_lease,
                )
                .await;
                publish_status(&config, &status, session.as_ref(), &children, &deps.status_store).await;
                session_rx = current_session_rx(&session, &dummy_rx);
            }
            _ = ticker.tick() => {
                // The attach device may have appeared without a config edit.
                let new_attach = deps.iface_lookup.get(&config.attach_iface_name).await;
                if new_attach.is_some() != attach.is_some() {
                    attach = new_attach;
                    ensure_session(&config, attach.as_ref(), &deps, &mut session).await;
                }
                reconcile(
                    &config,
                    &mut session,
                    attach.as_ref(),
                    &deps,
                    &mut children,
                    &mut last_nat_lease,
                )
                .await;
                publish_status(&config, &status, session.as_ref(), &children, &deps.status_store).await;
                session_rx = current_session_rx(&session, &dummy_rx);
            }
        }
    }

    // Teardown in reverse order: sections first, then the session.
    children.stop_all().await;
    if let Some(active) = session.take() {
        active.status.wait_stop().await;
    }
    status.just_change_status(ServiceStatus::Stop);
    deps.status_store.write().await.insert(key, LinkStatus::new(LinkState::Stop));
}

/// Returns the receiver to arm the loop's `changed()` on, synced to the current
/// state so a stale clone cannot spin the reconcile loop.
///
/// NOTE: syncing can race with a transition landing between the preceding
/// reconcile and `borrow_and_update()`; that single transition may then be
/// picked up by the 500ms ticker reconcile instead of immediately. The ticker
/// bounds the delay, which is the accepted trade-off for this minimal fix (a
/// generation/identity-based receiver swap would remove the delay).
fn current_session_rx(
    session: &Option<ActiveSession>,
    dummy: &watch::Receiver<SessionState>,
) -> watch::Receiver<SessionState> {
    match session {
        Some(s) => {
            let mut rx = s.rx.clone();
            // `clone()` copies the stored (stale) version. Sync it so `changed()`
            // waits for the next transition instead of firing forever.
            if rx.has_changed().is_err() {
                // Sender gone (session terminal/stopped): arming a closed channel
                // makes `changed()` return Err immediately every loop, so fall
                // back to the never-changing dummy.
                dummy.clone()
            } else {
                rx.borrow_and_update();
                rx
            }
        }
        None => dummy.clone(),
    }
}

async fn ensure_session(
    config: &WanLinkConfig,
    attach: Option<&LandscapeInterface>,
    deps: &WanLinkDeps,
    session: &mut Option<ActiveSession>,
) {
    // Tear down any running session when the link has no acquisition intent or
    // its attach iface is gone.
    let (Some(attach), true) = (attach, config.active()) else {
        if let Some(active) = session.take() {
            active.status.wait_stop().await;
        }
        return;
    };

    let new_key = SessionKey::from(config, attach);
    if session.as_ref().is_some_and(|active| active.key == new_key) {
        return;
    }

    if let Some(active) = session.take() {
        active.status.wait_stop().await;
    }
    let spec = resolve_session_spec(config, attach);
    let (tx, rx) = SessionSignal::new();
    let status = WatchService::new();
    deps.session_driver.spawn(config.id, attach.clone(), spec, status.clone(), tx).await;
    *session = Some(ActiveSession { status, rx, key: new_key });
}

/// Starts/stops sections so that the running set matches
/// `desired(config) AND session-ready`. A section is restarted when its own
/// resolved config changes (not only on a session transition), so editing e.g.
/// the NAT port range takes effect without touching the session.
#[allow(clippy::too_many_arguments)]
async fn reconcile(
    config: &WanLinkConfig,
    session: &mut Option<ActiveSession>,
    attach: Option<&LandscapeInterface>,
    deps: &WanLinkDeps,
    children: &mut SectionChildren,
    last_nat_lease: &mut Option<WanV4Lease>,
) {
    let state = session.as_ref().map(|s| s.rx.borrow().clone()).unwrap_or(SessionState::Idle);
    let lease = match &state {
        SessionState::Ready { lease } => *lease,
        _ => None,
    };
    let ready = state.is_ready();

    // The net iface exists when the session is ready (for pppd it is the ppp
    // device created by the session; otherwise it is the attach iface).
    let net_iface = if ready {
        let name = config.net_iface_name();
        match attach {
            Some(iface) if iface.name == name => Some(iface.clone()),
            _ => deps.iface_lookup.get(&name).await,
        }
    } else {
        None
    };

    let pd_ok = ready && config.pd.enable;
    let fw_ok = ready && config.firewall.enable;
    let mss_ok = ready && config.mss.enable;
    let nat_ok = ready && config.nat.enable && lease.is_some();

    if !pd_ok {
        if let Some((status, _)) = children.pd.take() {
            status.wait_stop().await;
        }
    }
    if !fw_ok {
        stop_any(&mut children.firewall).await;
    }
    if !mss_ok {
        if let Some((status, _)) = children.mss.take() {
            status.wait_stop().await;
        }
    }
    if !nat_ok {
        if let Some((status, _)) = children.nat.take() {
            status.wait_stop().await;
        }
        *last_nat_lease = None;
    }

    let Some(net) = net_iface else {
        return;
    };
    let link_id = config.id;

    if pd_ok {
        let desired_pd = PdSpec {
            mac: config.pd.mac,
            expected_pd_len: config.pd.expected_pd_len.unwrap_or(DEFAULT_PD_LEN),
        };
        let pd_needs = match &children.pd {
            Some((_, key)) => key != &desired_pd,
            None => true,
        };
        if pd_needs {
            if let Some((status, _)) = children.pd.take() {
                status.wait_stop().await;
            }
            let status = WatchService::new();
            deps.section_runner
                .spawn(link_id, net.clone(), SectionTask::Pd(desired_pd.clone()), status.clone())
                .await;
            children.pd = Some((status, desired_pd));
        }
    }

    if fw_ok && children.firewall.is_none() {
        let status = WatchService::new();
        deps.section_runner
            .spawn(link_id, net.clone(), SectionTask::Firewall, status.clone())
            .await;
        children.firewall = Some(status);
    }

    if mss_ok {
        // Only resolve when the section is actually enabled: a disabled MSS
        // must not trigger auto-derive (which warns on an ethernet link).
        // An explicit `clamp_size` is used verbatim; `None` derives from the
        // session kind (PPP only — `validate()` rejects ethernet + None).
        let desired_clamp = resolve_mss_clamp(config);
        let mss_needs = match &children.mss {
            Some((_, key)) => *key != desired_clamp,
            None => true,
        };
        if mss_needs {
            if let Some((status, _)) = children.mss.take() {
                status.wait_stop().await;
            }
            let status = WatchService::new();
            deps.section_runner
                .spawn(
                    link_id,
                    net.clone(),
                    SectionTask::Mss { clamp_size: desired_clamp },
                    status.clone(),
                )
                .await;
            children.mss = Some((status, desired_clamp));
        }
    }

    if nat_ok {
        let desired_nat = resolve_nat(&config.nat);
        let lease_now = lease.expect("nat requires a lease");
        let nat_needs = match &children.nat {
            Some((_, key)) => key != &desired_nat || *last_nat_lease != Some(lease_now),
            None => true,
        };
        if nat_needs {
            if let Some((status, _)) = children.nat.take() {
                status.wait_stop().await;
            }
            let status = WatchService::new();
            deps.section_runner
                .spawn(link_id, net.clone(), SectionTask::Nat(desired_nat.clone()), status.clone())
                .await;
            children.nat = Some((status, desired_nat));
            *last_nat_lease = Some(lease_now);
        }
    }
}

async fn publish_status(
    config: &WanLinkConfig,
    status: &WatchService,
    session: Option<&ActiveSession>,
    children: &SectionChildren,
    status_store: &LinkStatusStore,
) {
    let (pd, nat, firewall, mss) = children.statuses();
    let session_status = session.map(|s| s.status.current()).unwrap_or(ServiceStatus::Stop);

    let mut link_status = LinkStatus {
        state: LinkState::default(),
        session: session_status.clone(),
        pd,
        nat,
        firewall,
        mss,
    };
    link_status.refresh(config.active(), Some(session_status.clone()));

    if let Some(active) = session {
        if matches!(active.status.current(), ServiceStatus::Staring)
            && matches!(link_status.state, LinkState::Running | LinkState::Degraded)
        {
            active.status.just_change_status(ServiceStatus::Running);
        }
    }
    if link_status.state != LinkState::Idle && status.current() == ServiceStatus::Staring {
        // Keep the aggregate handle non-terminal while the link is alive.
        if matches!(link_status.state, LinkState::Running | LinkState::Degraded) {
            status.just_change_status(ServiceStatus::Running);
        }
    }

    status_store.write().await.insert(config.id.to_string(), link_status);
}

/// Spawns the instance task and returns the stop handle + config sender.
pub fn spawn_instance(
    config: WanLinkConfig,
    deps: Arc<WanLinkDeps>,
) -> (WatchService, mpsc::Sender<WanLinkConfig>) {
    let status = WatchService::new();
    let (tx, rx) = mpsc::channel(4);
    let task_status = status.clone();
    let resource = config.id.to_string();
    landscape_common::concurrency::spawn_task_with_resource(
        task_label::task::WAN_LINK_RUN,
        resource,
        async move { run_link_instance(config, task_status, rx, deps).await },
    );
    (status, tx)
}
