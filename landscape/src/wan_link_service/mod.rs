mod firewall;
mod mss;
mod nat;
mod pd;
mod v4;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::hub::iface::IfaceObserverAction;
use landscape_common::event::hub::{IAPrefixEventSender, IfaceEventReader};
use landscape_common::lan_service::lan_ipv6::{PdPrefixContext, PdPrefixContextMap};
use landscape_common::service::{
    ServiceHandle, ServiceStatus,
    controller::{ConfigStoreController, ConfigStoreServiceController},
    manager::{ServiceManager, ServiceStarterTrait},
};
use landscape_common::wan_link::{
    LinkState, LinkStateHandle, RuntimeWanLinkConfig, SectionKind, SessionIface, SessionPhase,
    SessionState, WanLinkConfig, WanLinkStatus, WanLinkStatusHandle, WanLinkStatusStore,
};
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;
use landscape_common::wan_service::ipv6_pd::config::DEFAULT_EXPECTED_PD_LEN;
use landscape_common::wan_service::ipv6_pd::{IAPrefixMap, IPV6PDPrefixStatus, LDIAPrefix};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::wan_service::pppoe::PppoeDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::wan_link::repository::WanLinkRepository;

use crate::get_iface_by_name;
use crate::sys_service::route::IpRouteService;

/// Backoff before re-spawning a run that ended on its own.
const DEFAULT_RESTART_BACKOFF: Duration = Duration::from_secs(5);
/// Cadence at which a running section samples its status into the display board.
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Config-update fan-out tag. `V4` changes cascade to dependents through the
/// `SessionState` rather than individual tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionTag {
    V4,
    Nat,
    Mss,
    Firewall,
    Pd,
}

enum Step {
    Stop,
    Restart,
    Ended,
}

/// Attach a section for a given session iface/config, then hold until stopped.
type SectionRunner =
    Arc<dyn Fn(SessionIface, WanLinkConfig, ServiceHandle) -> BoxFuture<'static, ()> + Send + Sync>;

/// One WAN link. The v4 section produces the link's `SessionState`; nat / mss /
/// firewall / pd wait on it and re-attach when the session is rebuilt or their
/// config changes. A dead run is retried after a backoff instead of failing the
/// link; per-section status is published to the store.
#[derive(Clone)]
pub struct WanLinkService {
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
    nat_dataplane: Arc<dyn NatDataplane>,
    mss_dataplane: Arc<dyn MssClampDataplane>,
    firewall_dataplane: Arc<dyn FirewallDataplane>,
    prefix_map: IAPrefixMap,
    prefix_sender: IAPrefixEventSender,
    shared_wan_iid: Arc<u64>,
    iface_events: broadcast::Sender<IfaceObserverAction>,
    config_channels: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>>,
    status_store: WanLinkStatusStore,
}

impl WanLinkService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
        nat_dataplane: Arc<dyn NatDataplane>,
        mss_dataplane: Arc<dyn MssClampDataplane>,
        firewall_dataplane: Arc<dyn FirewallDataplane>,
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
        iface_events: broadcast::Sender<IfaceObserverAction>,
        config_channels: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>>,
        status_store: WanLinkStatusStore,
    ) -> Self {
        Self {
            route_service,
            addr_binding,
            pppoe_dataplane,
            nat_dataplane,
            mss_dataplane,
            firewall_dataplane,
            prefix_map,
            prefix_sender,
            shared_wan_iid,
            iface_events,
            config_channels,
            status_store,
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for WanLinkService {
    type Config = WanLinkConfig;

    async fn start(&self, config: WanLinkConfig) -> ServiceHandle {
        let link_status = ServiceHandle::new();
        link_status.just_change_status(ServiceStatus::Staring);

        let active = config.active();

        // Absent at boot (hotplug) is tolerated: the environment task
        // establishes the carrier once the device appears.
        let carrier = get_iface_by_name(&config.attach_iface_name).await;
        if carrier.is_none() {
            tracing::info!(
                iface = %config.attach_iface_name,
                "WAN link attach interface not present yet; waiting for it to appear"
            );
        }
        let (link_state, state_rx) = LinkStateHandle::new(carrier);

        // Per-link config watch, so `handle_service_config` can deliver updates
        // without a full link restart.
        let (cfg_tx, cfg_rx) = watch::channel(config.clone());
        self.config_channels.lock().unwrap().insert(config.id, cfg_tx.clone());

        let (reconfig_tx, _reconfig_rx) = broadcast::channel(32);

        let board = WanLinkStatusHandle::new(config.id, self.status_store.clone(), active);
        board
            .set_session(if active { ServiceStatus::Staring } else { ServiceStatus::Disabled })
            .await;
        board.set_section(SectionKind::Pd, ServiceStatus::Stop).await;
        board.set_section(SectionKind::Nat, ServiceStatus::Stop).await;
        board.set_section(SectionKind::Firewall, ServiceStatus::Stop).await;
        board.set_section(SectionKind::Mss, ServiceStatus::Stop).await;

        {
            let status = link_status.clone();
            let task_status = status.clone();
            let link_state = link_state.clone();
            let iface_rx = self.iface_events.subscribe();
            let env_cfg_rx = cfg_rx.clone();
            let reconfig_tx = reconfig_tx.clone();
            let attach_iface = config.attach_iface_name.clone();
            let env_config = config.clone();
            let board = board.clone();
            status.spawn_task_with_resource(
                task_label::task::WAN_LINK_ENV,
                attach_iface.clone(),
                async move {
                    run_environment(
                        task_status,
                        link_state,
                        iface_rx,
                        env_cfg_rx,
                        reconfig_tx,
                        board,
                        env_config,
                    )
                    .await;
                },
            );
        }

        {
            let status = link_status.clone();
            let task_status = status.clone();
            let link_state = link_state.clone();
            let state_rx = state_rx.clone();
            let cfg_rx = cfg_rx.clone();
            let reconfig_rx = reconfig_tx.subscribe();
            let route_service = self.route_service.clone();
            let addr_binding = self.addr_binding.clone();
            let pppoe_dataplane = self.pppoe_dataplane.clone();
            let attach = config.attach_iface_name.clone();
            let board = board.clone();
            status.spawn_task_with_resource(
                task_label::task::WAN_LINK_V4_SUPERVISOR,
                attach.clone(),
                async move {
                    run_v4_supervisor(
                        task_status,
                        link_state,
                        board,
                        state_rx,
                        cfg_rx,
                        reconfig_rx,
                        route_service,
                        addr_binding,
                        pppoe_dataplane,
                        DEFAULT_RESTART_BACKOFF,
                    )
                    .await;
                },
            );
        }

        self.spawn_section(
            &link_status,
            &board,
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Nat,
            SectionKind::Nat,
            task_label::task::NAT_RUN,
            |cfg| cfg.nat.enable,
            |state| state.has_v4_lease(),
            {
                let dataplane = self.nat_dataplane.clone();
                Arc::new(move |iface, cfg, status| {
                    let dataplane = dataplane.clone();
                    Box::pin(async move {
                        nat::run(
                            iface,
                            RuntimeWanLinkConfig::from_config(&cfg).nat,
                            status,
                            dataplane,
                        )
                        .await;
                    })
                })
            },
        );

        self.spawn_section(
            &link_status,
            &board,
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Mss,
            SectionKind::Mss,
            task_label::task::MSS_CLAMP_RUN,
            |cfg| cfg.mss.enable,
            |state| state.is_up(),
            {
                let dataplane = self.mss_dataplane.clone();
                Arc::new(move |iface, cfg, status| {
                    let dataplane = dataplane.clone();
                    Box::pin(async move {
                        mss::run(
                            iface,
                            RuntimeWanLinkConfig::from_config(&cfg).mss,
                            status,
                            dataplane,
                        )
                        .await;
                    })
                })
            },
        );

        self.spawn_section(
            &link_status,
            &board,
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Firewall,
            SectionKind::Firewall,
            task_label::task::FIREWALL_RUN,
            |cfg| cfg.firewall.enable,
            |state| state.is_up(),
            {
                let dataplane = self.firewall_dataplane.clone();
                Arc::new(move |iface, cfg, status| {
                    let dataplane = dataplane.clone();
                    Box::pin(async move {
                        firewall::run(
                            iface,
                            RuntimeWanLinkConfig::from_config(&cfg).firewall,
                            status,
                            dataplane,
                        )
                        .await;
                    })
                })
            },
        );

        self.spawn_section(
            &link_status,
            &board,
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Pd,
            SectionKind::Pd,
            task_label::task::WAN_IPV6PD_OBSERVER,
            |cfg| cfg.pd.enable,
            |state| state.is_up(),
            {
                let route_service = self.route_service.clone();
                let addr_binding = self.addr_binding.clone();
                let prefix_map = self.prefix_map.clone();
                let prefix_sender = self.prefix_sender.clone();
                let shared_wan_iid = self.shared_wan_iid.clone();
                Arc::new(move |iface, cfg, status| {
                    let runtime = RuntimeWanLinkConfig::from_config(&cfg);
                    let route_service = route_service.clone();
                    let addr_binding = addr_binding.clone();
                    let prefix_map = prefix_map.clone();
                    let prefix_sender = prefix_sender.clone();
                    let shared_wan_iid = shared_wan_iid.clone();
                    Box::pin(async move {
                        pd::run(
                            runtime.id,
                            iface,
                            runtime.pd,
                            status,
                            route_service,
                            addr_binding,
                            prefix_map,
                            shared_wan_iid,
                            prefix_sender,
                        )
                        .await;
                    })
                })
            },
        );

        link_status.just_change_status(ServiceStatus::Running);

        link_status
    }
}

impl WanLinkService {
    #[allow(clippy::too_many_arguments)]
    fn spawn_section(
        &self,
        link_status: &ServiceHandle,
        board: &WanLinkStatusHandle,
        state_rx: watch::Receiver<LinkState>,
        cfg_rx: watch::Receiver<WanLinkConfig>,
        reconfig_rx: broadcast::Receiver<SectionTag>,
        tag: SectionTag,
        kind: SectionKind,
        label: &'static str,
        enabled: fn(&WanLinkConfig) -> bool,
        ready: fn(&SessionState) -> bool,
        runner: SectionRunner,
    ) {
        let status = link_status.clone();
        let task_status = status.clone();
        let board = board.clone();
        status.spawn_task(label, async move {
            run_dependent_section(
                task_status,
                board,
                state_rx,
                cfg_rx,
                reconfig_rx,
                tag,
                kind,
                label,
                enabled,
                ready,
                runner,
                DEFAULT_RESTART_BACKOFF,
            )
            .await;
        });
    }
}

/// Maintains the link's carrier and broadcasts `SectionTag`s on config change.
async fn run_environment(
    link_status: ServiceHandle,
    link_state: LinkStateHandle,
    mut iface_rx: broadcast::Receiver<IfaceObserverAction>,
    mut cfg_rx: watch::Receiver<WanLinkConfig>,
    reconfig_tx: broadcast::Sender<SectionTag>,
    board: WanLinkStatusHandle,
    initial_config: WanLinkConfig,
) {
    let stop = link_status.stop_token();
    let mut applied = initial_config.clone();
    let mut attach_iface = initial_config.attach_iface_name.clone();

    // Cover an iface that appeared between `start`'s lookup and this subscription.
    if let Some(iface) = get_iface_by_name(&attach_iface).await {
        link_state.set_carrier(Some(iface));
    }

    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            event = iface_rx.recv() => match event {
                Ok(IfaceObserverAction::Up(name)) => {
                    if name == attach_iface
                        && let Some(iface) = get_iface_by_name(&attach_iface).await
                    {
                        link_state.set_carrier(Some(iface));
                    }
                }
                Ok(IfaceObserverAction::Down(name)) => {
                    if name == attach_iface {
                        link_state.set_carrier(None);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    match get_iface_by_name(&attach_iface).await {
                        Some(iface) => link_state.set_carrier(Some(iface)),
                        None => link_state.set_carrier(None),
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            changed = cfg_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let new = cfg_rx.borrow_and_update().clone();

                if new.attach_iface_name != attach_iface {
                    attach_iface = new.attach_iface_name.clone();
                    match get_iface_by_name(&attach_iface).await {
                        Some(iface) => link_state.set_carrier(Some(iface)),
                        None => link_state.set_carrier(None),
                    }
                }

                if new.active() != applied.active() {
                    board.set_active(new.active()).await;
                }

                for tag in config_change_tags(&applied, &new) {
                    let _ = reconfig_tx.send(tag);
                }
                applied = new;
            }
        }
    }
}

/// Section tags a config change requires.
///
/// `V4` covers an `active()` flip too: an ethernet link with v4 disabled anchors
/// its session only while PD is enabled, so `pd.enable true -> false` must
/// restart v4 to drop the lease-less anchor and its sections.
fn config_change_tags(applied: &WanLinkConfig, new: &WanLinkConfig) -> Vec<SectionTag> {
    let mut tags = Vec::new();

    let v4_relevant = new.kind != applied.kind
        || new.attach_iface_name != applied.attach_iface_name
        || new.v4 != applied.v4
        || new.active() != applied.active();
    if v4_relevant {
        tags.push(SectionTag::V4);
    }

    // Resolved-spec diff: normalized defaults must not respawn.
    let new_rt = RuntimeWanLinkConfig::from_config(new);
    let old_rt = RuntimeWanLinkConfig::from_config(applied);
    if new_rt.nat != old_rt.nat {
        tags.push(SectionTag::Nat);
    }
    if new_rt.mss != old_rt.mss {
        tags.push(SectionTag::Mss);
    }
    if new_rt.firewall != old_rt.firewall {
        tags.push(SectionTag::Firewall);
    }
    if new_rt.pd != old_rt.pd {
        tags.push(SectionTag::Pd);
    }

    tags
}

async fn wait_carrier_up(
    state_rx: &mut watch::Receiver<LinkState>,
    stop: &CancellationToken,
) -> bool {
    loop {
        if state_rx.borrow_and_update().carrier.is_some() {
            return true;
        }
        tokio::select! {
            _ = stop.cancelled() => return false,
            changed = state_rx.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
        }
    }
}

async fn wait_carrier_invalidated(state_rx: &mut watch::Receiver<LinkState>, ifindex: u32) {
    loop {
        {
            let snapshot = state_rx.borrow_and_update();
            match &snapshot.carrier {
                None => return,
                Some(carrier) if carrier.index != ifindex => return,
                Some(_) => {}
            }
        }
        if state_rx.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_session_ready(
    state_rx: &mut watch::Receiver<LinkState>,
    stop: &CancellationToken,
    ready: fn(&SessionState) -> bool,
) -> bool {
    loop {
        if ready(&state_rx.borrow_and_update().session) {
            return true;
        }
        tokio::select! {
            _ = stop.cancelled() => return false,
            changed = state_rx.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
        }
    }
}

async fn wait_session_invalidated(state_rx: &mut watch::Receiver<LinkState>, epoch: u64) {
    loop {
        {
            let snapshot = state_rx.borrow_and_update();
            if !snapshot.session.is_up() || snapshot.session.epoch != epoch {
                return;
            }
        }
        if state_rx.changed().await.is_err() {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_v4_supervisor(
    link_status: ServiceHandle,
    link_state: LinkStateHandle,
    board: WanLinkStatusHandle,
    mut state_rx: watch::Receiver<LinkState>,
    mut cfg_rx: watch::Receiver<WanLinkConfig>,
    mut reconfig_rx: broadcast::Receiver<SectionTag>,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
    backoff: Duration,
) {
    let stop = link_status.stop_token();

    loop {
        let cfg = cfg_rx.borrow_and_update().clone();
        if !cfg.active() {
            board.set_session(ServiceStatus::Disabled).await;
            tokio::select! {
                _ = stop.cancelled() => return,
                event = reconfig_rx.recv() => {
                    if matches!(event, Err(broadcast::error::RecvError::Closed)) {
                        return;
                    }
                }
            }
            continue;
        }

        if !wait_carrier_up(&mut state_rx, &stop).await {
            return;
        }
        let Some(iface) = state_rx.borrow_and_update().carrier.clone() else {
            continue;
        };
        let run_ifindex = iface.index;
        let runtime = RuntimeWanLinkConfig::from_config(&cfg);

        let run = ServiceHandle::new();
        run.just_change_status(ServiceStatus::Staring);
        board.set_session(run.current()).await;
        let run_child = run.clone();
        let session = Some(link_state.clone());
        let rs = route_service.clone();
        let ab = addr_binding.clone();
        let dp = pppoe_dataplane.clone();
        let resource = iface.name.clone();
        let join = run.spawn_task_with_resource(
            task_label::task::WAN_LINK_V4_SUPERVISOR,
            resource,
            async move {
                v4::run(iface, runtime, run_child, rs, ab, dp, session).await;
            },
        );
        tokio::pin!(join);

        let mut status_ticker = tokio::time::interval(STATUS_POLL_INTERVAL);
        let mut retry = false;

        loop {
            let mut step: Option<Step> = None;
            tokio::select! {
                _ = stop.cancelled() => step = Some(Step::Stop),
                _ = wait_carrier_invalidated(&mut state_rx, run_ifindex) => step = Some(Step::Restart),
                event = reconfig_rx.recv() => match event {
                    Ok(SectionTag::V4) => step = Some(Step::Restart),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => step = Some(Step::Stop),
                },
                _ = &mut join => step = Some(Step::Ended),
                _ = status_ticker.tick() => {
                    board.set_session(run.current()).await;
                }
            }

            match step {
                None => continue,
                Some(Step::Stop) => {
                    run.wait_stop().await;
                    board.set_session(run.current()).await;
                    return;
                }
                Some(Step::Restart) => {
                    link_state.session_down();
                    run.wait_stop().await;
                    board.set_session(ServiceStatus::Stop).await;
                    break;
                }
                Some(Step::Ended) => {
                    link_state.session_down();
                    board.set_session(run.current()).await;
                    retry = true;
                    break;
                }
            }
        }

        if retry {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_dependent_section(
    link_status: ServiceHandle,
    board: WanLinkStatusHandle,
    mut state_rx: watch::Receiver<LinkState>,
    mut cfg_rx: watch::Receiver<WanLinkConfig>,
    mut reconfig_rx: broadcast::Receiver<SectionTag>,
    my_tag: SectionTag,
    kind: SectionKind,
    label: &'static str,
    enabled: fn(&WanLinkConfig) -> bool,
    ready: fn(&SessionState) -> bool,
    runner: SectionRunner,
    backoff: Duration,
) {
    let stop = link_status.stop_token();

    loop {
        let cfg = cfg_rx.borrow_and_update().clone();
        if !enabled(&cfg) {
            board.set_section(kind, ServiceStatus::Stop).await;
            let mut stop_now = false;
            tokio::select! {
                _ = stop.cancelled() => stop_now = true,
                event = reconfig_rx.recv() => {
                    if matches!(event, Err(broadcast::error::RecvError::Closed)) {
                        stop_now = true;
                    }
                }
            }
            if stop_now {
                return;
            }
            continue;
        }

        if !wait_session_ready(&mut state_rx, &stop, ready).await {
            board.set_section(kind, ServiceStatus::Stop).await;
            return;
        }
        let (iface, epoch) = {
            let snapshot = state_rx.borrow_and_update();
            match &snapshot.session.phase {
                SessionPhase::Up { iface, .. } => (iface.clone(), snapshot.session.epoch),
                SessionPhase::Down => continue,
            }
        };

        let run = ServiceHandle::new();
        run.just_change_status(ServiceStatus::Staring);
        board.set_section(kind, run.current()).await;
        let run_child = run.clone();
        let runner = runner.clone();
        let iface_child = iface.clone();
        let cfg_child = cfg.clone();
        let resource = iface.iface_name.clone();
        let join = run.spawn_task_with_resource(label, resource, async move {
            runner(iface_child, cfg_child, run_child).await;
        });
        tokio::pin!(join);

        let mut status_ticker = tokio::time::interval(STATUS_POLL_INTERVAL);
        let mut retry = false;

        loop {
            let mut step: Option<Step> = None;
            tokio::select! {
                _ = stop.cancelled() => step = Some(Step::Stop),
                _ = wait_session_invalidated(&mut state_rx, epoch) => step = Some(Step::Restart),
                event = reconfig_rx.recv() => match event {
                    Ok(tag) if tag == my_tag => step = Some(Step::Restart),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => step = Some(Step::Stop),
                },
                _ = &mut join => step = Some(Step::Ended),
                _ = status_ticker.tick() => {
                    board.set_section(kind, run.current()).await;
                }
            }

            match step {
                None => continue,
                Some(Step::Stop) => {
                    run.wait_stop().await;
                    board.set_section(kind, run.current()).await;
                    return;
                }
                Some(Step::Restart) => {
                    run.wait_stop().await;
                    board.set_section(kind, ServiceStatus::Stop).await;
                    break;
                }
                Some(Step::Ended) => {
                    board.set_section(kind, run.current()).await;
                    retry = true;
                    break;
                }
            }
        }

        if retry {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
        }
    }
}

#[derive(Clone)]
pub struct WanLinkServiceManagerService {
    store: WanLinkRepository,
    service: ServiceManager<WanLinkService>,
    prefix_map: IAPrefixMap,
    config_channels: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>>,
    status_store: WanLinkStatusStore,
}

#[async_trait::async_trait]
impl ConfigStoreController for WanLinkServiceManagerService {
    type Id = Uuid;
    type Config = WanLinkConfig;
    type Store = WanLinkRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

#[async_trait::async_trait]
impl ConfigStoreServiceController for WanLinkServiceManagerService {
    type H = WanLinkService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    /// A running link receives the new config over its per-link watch (partial
    /// reconfigure); a link that is not running is started via bounded delivery.
    async fn handle_service_config(&self, config: Self::Config) -> Result<Self::Config, DbError> {
        let change = self.get_store().upsert_preserving_chain_id(config).await?;
        self.notify_changed(vec![change.clone()]).await;
        let saved = change.new;

        let delivered = {
            let guard = self.config_channels.lock().unwrap();
            guard.get(&saved.id).map(|tx| tx.send(saved.clone()).is_ok()).unwrap_or(false)
        };

        if !delivered {
            self.get_service().deliver_bounded(saved.clone(), self.deliver_timeout()).await;
        }

        Ok(saved)
    }

    async fn delete_and_stop_service(
        &self,
        id: Self::Id,
    ) -> Result<Option<ServiceStatus>, DbError> {
        let old = self.get_store().delete_and_get(id).await?;
        let Some(old) = old else { return Ok(None) };
        let status = self.get_service().stop_service(id.to_string()).await;
        self.status_store.write().await.remove(&id);
        self.config_channels.lock().unwrap().remove(&id);
        self.notify_deleted(old).await;
        Ok(status)
    }
}

impl WanLinkServiceManagerService {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        store_service: LandscapeDBServiceProvider,
        mut dev_observer: IfaceEventReader,
        route_service: IpRouteService,
        addr_binding: Arc<dyn WanAddrBinding>,
        pppoe_dataplane: Arc<dyn PppoeDataplane>,
        nat_dataplane: Arc<dyn NatDataplane>,
        mss_dataplane: Arc<dyn MssClampDataplane>,
        firewall_dataplane: Arc<dyn FirewallDataplane>,
        prefix_map: IAPrefixMap,
        prefix_sender: IAPrefixEventSender,
        shared_wan_iid: Arc<u64>,
    ) -> Self {
        let store = store_service.wan_link_store();

        let (iface_events, _) = broadcast::channel(128);
        let config_channels: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let status_store: WanLinkStatusStore = Arc::default();

        let starter = WanLinkService::new(
            route_service,
            addr_binding,
            pppoe_dataplane,
            nat_dataplane,
            mss_dataplane,
            firewall_dataplane,
            prefix_map.clone(),
            prefix_sender,
            shared_wan_iid,
            iface_events.clone(),
            config_channels.clone(),
            status_store.clone(),
        );
        let service = ServiceManager::init(store.list().await.unwrap(), starter).await;

        let forward_tx = iface_events.clone();
        spawn_task(task_label::task::WAN_LINK_OBSERVER, async move {
            loop {
                match dev_observer.recv().await {
                    Ok(msg) => {
                        let _ = forward_tx.send(msg);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Self {
            service,
            store,
            prefix_map,
            config_channels,
            status_store,
        }
    }

    /// Keyed by the wan link uuid (stringified for the REST view).
    pub fn get_ipv6_prefix_infos(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.prefix_map
            .get_info()
            .into_iter()
            .map(|(id, prefix)| (id.to_string(), prefix))
            .collect()
    }

    /// Keyed by the wan link uuid (stringified for the REST view).
    pub fn get_ipv6_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        self.prefix_map
            .get_prefix_statuses()
            .into_iter()
            .map(|(id, status)| (id.to_string(), status))
            .collect()
    }

    pub async fn get_link_statuses(&self) -> HashMap<String, WanLinkStatus> {
        self.status_store
            .read()
            .await
            .iter()
            .map(|(id, status)| (id.to_string(), status.clone()))
            .collect()
    }

    pub async fn get_pd_prefix_contexts(&self) -> PdPrefixContextMap {
        self.store
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|config| config.pd.enable)
            .map(|config| {
                let actual_prefix = self.prefix_map.load_actual(&config.id);
                (
                    config.id,
                    PdPrefixContext {
                        expected_pd_len: config
                            .pd
                            .expected_pd_len
                            .unwrap_or(DEFAULT_EXPECTED_PD_LEN),
                        actual_prefix,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
