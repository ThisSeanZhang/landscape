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
    LinkState, LinkStateHandle, RuntimeWanLinkConfig, SessionIface, SessionPhase, WanLinkConfig,
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

/// Which section a config update affects; the environment task broadcasts
/// only the changed tags, and each supervisor re-attaches on its own tag.
/// `V4` changes cascade through the `SessionState` (Down → Up), not tags.
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

type SectionRunner =
    Arc<dyn Fn(SessionIface, WanLinkConfig, ServiceHandle) -> BoxFuture<'static, ()> + Send + Sync>;

/// Keeps a run that keeps ending on its own without `Failed` (e.g. a panic)
/// from spinning the restart loop hot.
const ENDED_RESTART_PAUSE: Duration = Duration::from_secs(1);

/// One WAN link = one service instance owning the full uplink lifecycle.
///
/// `start` spawns one supervisor per section: v4 acquisition produces the
/// link's `SessionState`; nat / mss / firewall / pd wait for the session and
/// re-attach when it is rebuilt or their config changes. A section terminal
/// failure tears down the whole link (the link is healthy as a whole).
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
        }
    }
}

#[async_trait::async_trait]
impl ServiceStarterTrait for WanLinkService {
    type Config = WanLinkConfig;

    async fn start(&self, config: WanLinkConfig) -> ServiceHandle {
        let link_status = ServiceHandle::new();

        // A missing attach iface is not fatal: the link waits for the
        // carrier (hot plug).
        let carrier = get_iface_by_name(&config.attach_iface_name).await;
        if carrier.is_none() {
            tracing::warn!(
                "WAN link attach interface {} not found yet; waiting for carrier",
                config.attach_iface_name
            );
        }

        link_status.just_change_status(ServiceStatus::Staring);

        let (link_state, state_rx) = LinkStateHandle::new(carrier);

        // Registered so `handle_service_config` can deliver updates without a
        // full link restart.
        let (cfg_tx, cfg_rx) = watch::channel(config.clone());
        self.config_channels.lock().unwrap().insert(config.id, cfg_tx.clone());

        // Deregister on exit so a stopped link falls back to
        // `deliver_bounded`; `same_channel` avoids removing a restarted
        // successor's entry.
        {
            let config_channels = self.config_channels.clone();
            let id = config.id;
            let registered = cfg_tx.clone();
            let stop = link_status.stop_token();
            spawn_task(task_label::task::WAN_LINK_CLEANUP, async move {
                stop.cancelled().await;
                let mut guard = config_channels.lock().unwrap();
                if guard.get(&id).is_some_and(|current| current.same_channel(&registered)) {
                    guard.remove(&id);
                }
            });
        }

        let (reconfig_tx, _reconfig_rx) = broadcast::channel(32);

        {
            let status = link_status.clone();
            let task_status = status.clone();
            let link_state = link_state.clone();
            let iface_rx = self.iface_events.subscribe();
            let env_cfg_rx = cfg_rx.clone();
            let reconfig_tx = reconfig_tx.clone();
            let attach_iface = config.attach_iface_name.clone();
            let env_config = config.clone();
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
                        env_config,
                    )
                    .await;
                },
            );
        }

        // v4 supervisor
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
            status.spawn_task_with_resource(
                task_label::task::WAN_LINK_V4_SUPERVISOR,
                attach.clone(),
                async move {
                    run_v4_supervisor(
                        task_status,
                        link_state,
                        state_rx,
                        cfg_rx,
                        reconfig_rx,
                        route_service,
                        addr_binding,
                        pppoe_dataplane,
                    )
                    .await;
                },
            );
        }

        // dependent section supervisors
        self.spawn_section(
            &link_status,
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Nat,
            task_label::task::NAT_RUN,
            |cfg| cfg.nat.enable,
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
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Mss,
            task_label::task::MSS_CLAMP_RUN,
            |cfg| cfg.mss.enable,
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
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Firewall,
            task_label::task::FIREWALL_RUN,
            |cfg| cfg.firewall.enable,
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
            state_rx.clone(),
            cfg_rx.clone(),
            reconfig_tx.subscribe(),
            SectionTag::Pd,
            task_label::task::WAN_IPV6PD_OBSERVER,
            |cfg| cfg.pd.enable,
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

        // The service tree is up; connectivity is expressed by the section
        // state, not this status.
        link_status.just_change_status(ServiceStatus::Running);

        link_status
    }
}

impl WanLinkService {
    #[allow(clippy::too_many_arguments)]
    fn spawn_section(
        &self,
        link_status: &ServiceHandle,
        state_rx: watch::Receiver<LinkState>,
        cfg_rx: watch::Receiver<WanLinkConfig>,
        reconfig_rx: broadcast::Receiver<SectionTag>,
        tag: SectionTag,
        label: &'static str,
        enabled: fn(&WanLinkConfig) -> bool,
        runner: SectionRunner,
    ) {
        let status = link_status.clone();
        let task_status = status.clone();
        status.spawn_task(label, async move {
            run_dependent_section(
                task_status,
                state_rx,
                cfg_rx,
                reconfig_rx,
                tag,
                label,
                enabled,
                runner,
            )
            .await;
        });
    }
}

/// Maintains the carrier from iface events; on config updates broadcasts the
/// `SectionTag`s whose slice changed.
async fn run_environment(
    link_status: ServiceHandle,
    link_state: LinkStateHandle,
    mut iface_rx: broadcast::Receiver<IfaceObserverAction>,
    mut cfg_rx: watch::Receiver<WanLinkConfig>,
    reconfig_tx: broadcast::Sender<SectionTag>,
    initial_config: WanLinkConfig,
) {
    let stop = link_status.stop_token();
    let mut applied = initial_config.clone();
    let mut attach_iface = initial_config.attach_iface_name.clone();

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

                let structural = new.kind != applied.kind
                    || new.attach_iface_name != applied.attach_iface_name
                    || new.v4 != applied.v4;
                if structural {
                    let _ = reconfig_tx.send(SectionTag::V4);
                }
                if new.nat != applied.nat {
                    let _ = reconfig_tx.send(SectionTag::Nat);
                }
                if new.mss != applied.mss {
                    let _ = reconfig_tx.send(SectionTag::Mss);
                }
                if new.firewall != applied.firewall {
                    let _ = reconfig_tx.send(SectionTag::Firewall);
                }
                if new.pd != applied.pd {
                    let _ = reconfig_tx.send(SectionTag::Pd);
                }
                applied = new;
            }
        }
    }
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

async fn wait_session_up(
    state_rx: &mut watch::Receiver<LinkState>,
    stop: &CancellationToken,
) -> bool {
    loop {
        if state_rx.borrow_and_update().session.is_up() {
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

async fn wait_carrier_down(state_rx: &mut watch::Receiver<LinkState>) {
    loop {
        if state_rx.borrow_and_update().carrier.is_none() {
            return;
        }
        if state_rx.changed().await.is_err() {
            return;
        }
    }
}

/// Resolves once the session is down or its epoch has moved past `epoch`.
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

/// The v4 acquisition supervisor: (re)starts the v4 driver whenever the
/// carrier is up, and cancels it on carrier loss or v4-relevant config change.
#[allow(clippy::too_many_arguments)]
async fn run_v4_supervisor(
    link_status: ServiceHandle,
    link_state: LinkStateHandle,
    mut state_rx: watch::Receiver<LinkState>,
    mut cfg_rx: watch::Receiver<WanLinkConfig>,
    mut reconfig_rx: broadcast::Receiver<SectionTag>,
    route_service: IpRouteService,
    addr_binding: Arc<dyn WanAddrBinding>,
    pppoe_dataplane: Arc<dyn PppoeDataplane>,
) {
    let stop = link_status.stop_token();

    loop {
        if !wait_carrier_up(&mut state_rx, &stop).await {
            return;
        }
        let Some(iface) = state_rx.borrow_and_update().carrier.clone() else {
            continue;
        };
        let cfg = cfg_rx.borrow_and_update().clone();
        let runtime = RuntimeWanLinkConfig::from_config(&cfg);

        let run = ServiceHandle::new();
        run.just_change_status(ServiceStatus::Staring);
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

        loop {
            let mut step: Option<Step> = None;
            tokio::select! {
                _ = stop.cancelled() => step = Some(Step::Stop),
                _ = wait_carrier_down(&mut state_rx) => step = Some(Step::Restart),
                event = reconfig_rx.recv() => match event {
                    Ok(SectionTag::V4) => step = Some(Step::Restart),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => step = Some(Step::Stop),
                },
                _ = &mut join => step = Some(Step::Ended),
            }

            match step {
                None => continue,
                Some(Step::Stop) => {
                    run.wait_stop().await;
                    return;
                }
                Some(Step::Restart) => {
                    link_state.session_down();
                    run.wait_stop().await;
                    break;
                }
                Some(Step::Ended) => {
                    link_state.session_down();
                    if matches!(run.current(), ServiceStatus::Failed) {
                        link_status.just_change_status(ServiceStatus::Failed);
                        return;
                    }
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tokio::time::sleep(ENDED_RESTART_PAUSE) => {}
                    }
                    break;
                }
            }
        }
    }
}

/// Waits for the session, attaches the section, and re-attaches when the
/// session is rebuilt or the section config changes.
#[allow(clippy::too_many_arguments)]
async fn run_dependent_section(
    link_status: ServiceHandle,
    mut state_rx: watch::Receiver<LinkState>,
    mut cfg_rx: watch::Receiver<WanLinkConfig>,
    mut reconfig_rx: broadcast::Receiver<SectionTag>,
    my_tag: SectionTag,
    label: &'static str,
    enabled: fn(&WanLinkConfig) -> bool,
    runner: SectionRunner,
) {
    let stop = link_status.stop_token();

    loop {
        let cfg = cfg_rx.borrow_and_update().clone();
        if !enabled(&cfg) {
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

        if !wait_session_up(&mut state_rx, &stop).await {
            return;
        }
        let (iface, epoch) = {
            let snapshot = state_rx.borrow_and_update();
            match &snapshot.session.phase {
                SessionPhase::Up(iface) => (iface.clone(), snapshot.session.epoch),
                SessionPhase::Down => continue,
            }
        };

        let run = ServiceHandle::new();
        run.just_change_status(ServiceStatus::Staring);
        let run_child = run.clone();
        let runner = runner.clone();
        let iface_child = iface.clone();
        let cfg_child = cfg.clone();
        let resource = iface.iface_name.clone();
        let join = run.spawn_task_with_resource(label, resource, async move {
            runner(iface_child, cfg_child, run_child).await;
        });
        tokio::pin!(join);

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
            }

            match step {
                None => continue,
                Some(Step::Stop) => {
                    run.wait_stop().await;
                    return;
                }
                Some(Step::Restart) => {
                    run.wait_stop().await;
                    break;
                }
                Some(Step::Ended) => {
                    if matches!(run.current(), ServiceStatus::Failed) {
                        link_status.just_change_status(ServiceStatus::Failed);
                        return;
                    }
                    tokio::select! {
                        _ = stop.cancelled() => return,
                        _ = tokio::time::sleep(ENDED_RESTART_PAUSE) => {}
                    }
                    break;
                }
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

    /// Persist-first delivery with partial restart: a running link is
    /// reconfigured over its per-link watch; a non-running link falls back
    /// to the generic bounded delivery.
    async fn handle_service_config(&self, config: Self::Config) -> Result<Self::Config, DbError> {
        let change = self.get_store().checked_upsert(config).await?;
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

        // Forwarded, not acted on: each link maintains its own carrier state.
        let (iface_events, _) = broadcast::channel(128);
        let config_channels: Arc<Mutex<HashMap<Uuid, watch::Sender<WanLinkConfig>>>> =
            Arc::new(Mutex::new(HashMap::new()));

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

        Self { service, store, prefix_map, config_channels }
    }

    /// Obtained IA-PD prefixes per section iface (read-only status view).
    pub fn get_ipv6_prefix_infos(&self) -> HashMap<String, Option<LDIAPrefix>> {
        self.prefix_map.get_info()
    }

    /// IA-PD negotiation status per section iface (read-only status view).
    pub fn get_ipv6_prefix_statuses(&self) -> HashMap<String, IPV6PDPrefixStatus> {
        self.prefix_map.get_prefix_statuses()
    }

    /// PD context of every link with an enabled PD section, keyed by the
    /// iface the PD client runs on (the ppp device for pppd links). Used by
    /// LAN IPv6 config validation for prefix capacity planning.
    pub async fn get_pd_prefix_contexts(&self) -> PdPrefixContextMap {
        self.store
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|config| config.pd.enable)
            .map(|config| {
                let iface_name =
                    RuntimeWanLinkConfig::from_config(&config).section_iface_name().to_string();
                let actual_prefix = self.prefix_map.load_actual(&iface_name);
                (
                    iface_name,
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
