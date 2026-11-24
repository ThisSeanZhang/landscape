use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use uuid::Uuid;

use arc_swap::ArcSwap;
use landscape_common::service::manager::{ServiceManager, ServiceStarterTrait};
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{
    HealthCheckRuntime, LinkStateHandle, SectionKind, SessionIface, WanLinkConfig, WanLinkKind,
    WanLinkStatusHandle, WanV4Lease,
};

use super::config_updates::LinkConfigUpdates;
use super::{
    SectionRunner, SectionScope, SectionTag, config_change_tags, link_default_intents,
    run_dependent_section,
};

fn link_config(nat_enable: bool) -> WanLinkConfig {
    serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "nat": { "enable": nat_enable }
    }))
    .unwrap()
}

fn pppd_kind(password: &str) -> WanLinkKind {
    WanLinkKind::Pppd {
        ppp_iface_name: "ppp0".into(),
        peer_id: "user".into(),
        password: password.into(),
        ac: None,
        plugin: Default::default(),
    }
}

#[test]
fn live_config_compares_kind_variants_and_retries_a_failed_instance() {
    let updates = LinkConfigUpdates::new(Arc::default());
    let mut cfg = link_config(false);
    let mut rx = updates.start(cfg.clone()).1.subscribe();
    let native: WanLinkKind = serde_json::from_value(serde_json::json!({
        "t": "pppoe_native", "requested_mru": 1492
    }))
    .unwrap();
    for kind in [pppd_kind("one"), native, WanLinkKind::Ethernet] {
        cfg.kind = kind;
        cfg.update_at += 1.0;
        assert!(updates.queue(&cfg));
        assert!(rx.has_changed().is_err());
        let (started, next_rx) = updates.start(cfg.clone());
        assert_eq!(started, cfg);
        rx = next_rx.subscribe();
        drop(next_rx);
    }
    drop(rx);
    cfg.update_at += 1.0;
    assert!(updates.queue(&cfg));
}

#[derive(Debug)]
struct RunningLink {
    initial: WanLinkConfig,
    updates: watch::Receiver<WanLinkConfig>,
    status: ServiceHandle,
    finish_cleanup: oneshot::Sender<()>,
}

#[derive(Clone)]
struct TestLinkStarter {
    updates: Arc<LinkConfigUpdates>,
    starts: mpsc::UnboundedSender<RunningLink>,
}

#[async_trait::async_trait]
impl ServiceStarterTrait for TestLinkStarter {
    type Config = WanLinkConfig;

    async fn start(&self, config: WanLinkConfig) -> ServiceHandle {
        let (initial, config_tx) = self.updates.start(config);
        let updates = config_tx.subscribe();
        let status = ServiceHandle::new();
        status.just_change_status(ServiceStatus::Staring);
        let worker = status.clone();
        let (finish_cleanup, cleanup) = oneshot::channel();
        status.spawn_task("wan.link.test", async move {
            worker.stop_token().cancelled().await;
            let _ = cleanup.await;
            worker.just_change_status(ServiceStatus::Stop);
        });
        status.just_change_status(ServiceStatus::Running);
        self.starts
            .send(RunningLink {
                initial,
                updates,
                status: status.clone(),
                finish_cleanup,
            })
            .unwrap();
        status
    }
}

#[tokio::test]
async fn kind_restart_drains_the_old_run_and_starts_with_the_latest_save() {
    let timeout = Duration::from_secs(3);
    let updates = Arc::new(LinkConfigUpdates::new(Arc::default()));
    let (starts, mut started) = mpsc::unbounded_channel();
    let first = link_config(false);
    let starter = TestLinkStarter { updates: updates.clone(), starts };
    let manager = ServiceManager::init(vec![first.clone()], starter).await;
    let old = tokio::time::timeout(timeout, started.recv()).await.unwrap().unwrap();

    let mut next = first.clone();
    next.kind = pppd_kind("one");
    next.update_at += 1.0;
    updates.deliver(&manager, &next, timeout).await;
    tokio::time::timeout(timeout, old.status.stop_token().cancelled()).await.unwrap();

    let mut latest = next.clone();
    latest.kind = pppd_kind("two");
    latest.update_at += 1.0;
    updates.deliver(&manager, &latest, timeout).await;
    updates.deliver(&manager, &next, timeout).await; // A delayed notification for the older write.
    assert_eq!(*old.updates.borrow(), first);
    assert!(started.try_recv().is_err());
    old.finish_cleanup.send(()).unwrap();

    let mut new = tokio::time::timeout(timeout, started.recv()).await.unwrap().unwrap();
    assert_eq!(old.status.current(), ServiceStatus::Stop);
    assert_eq!(new.initial, latest);
    latest.kind = pppd_kind("three");
    latest.update_at += 1.0;
    assert!(!updates.queue(&latest));
    assert!(new.updates.has_changed().unwrap());
    assert_eq!(*new.updates.borrow_and_update(), latest);
    assert!(!updates.queue(&next));
    assert!(!new.updates.has_changed().unwrap());
    new.finish_cleanup.send(()).unwrap();
    manager.stop_all().await;
}

#[tokio::test]
async fn deleting_a_draining_link_withdraws_its_queued_restart() {
    let timeout = Duration::from_secs(3);
    let updates = Arc::new(LinkConfigUpdates::new(Arc::default()));
    let (starts, mut started) = mpsc::unbounded_channel();
    let mut cfg = link_config(false);
    let starter = TestLinkStarter { updates: updates.clone(), starts };
    let manager = ServiceManager::init(vec![cfg.clone()], starter).await;
    let old = tokio::time::timeout(timeout, started.recv()).await.unwrap().unwrap();

    cfg.kind = pppd_kind("one");
    cfg.update_at += 1.0;
    updates.deliver(&manager, &cfg, timeout).await;
    tokio::time::timeout(timeout, old.status.stop_token().cancelled()).await.unwrap();
    {
        let stop = manager.stop_service(cfg.id.to_string());
        tokio::pin!(stop);
        assert!(futures::poll!(stop.as_mut()).is_pending());
        old.finish_cleanup.send(()).unwrap();
        assert_eq!(stop.await, Some(ServiceStatus::Stop));
    }
    updates.remove(cfg.id);
    drop(manager);
    assert!(tokio::time::timeout(timeout, started.recv()).await.unwrap().is_none());
}

#[tokio::test]
async fn saves_during_failed_setup_start_the_latest_config() {
    #[derive(Clone)]
    struct FailingSetup {
        updates: Arc<LinkConfigUpdates>,
        attempts: mpsc::UnboundedSender<(WanLinkConfig, oneshot::Sender<()>)>,
    }

    #[async_trait::async_trait]
    impl ServiceStarterTrait for FailingSetup {
        type Config = WanLinkConfig;

        async fn start(&self, config: WanLinkConfig) -> ServiceHandle {
            let status = ServiceHandle::new();
            status.just_change_status(ServiceStatus::Staring);
            let (config, _tx) = self.updates.start(config);
            let (finish, setup) = oneshot::channel();
            self.attempts.send((config, finish)).unwrap();
            setup.await.unwrap();
            status.just_change_status(ServiceStatus::Failed);
            status
        }
    }

    let timeout = Duration::from_secs(3);
    let updates = Arc::new(LinkConfigUpdates::new(Arc::default()));
    let (attempts, mut started) = mpsc::unbounded_channel();
    let mut config = link_config(false);
    let manager = ServiceManager::init(
        vec![config.clone()],
        FailingSetup { updates: updates.clone(), attempts },
    )
    .await;
    let (_, fail) = tokio::time::timeout(timeout, started.recv()).await.unwrap().unwrap();
    config.update_at += 1.0;
    config.nat.enable = true;
    updates.deliver(&manager, &config, timeout).await;
    config.update_at += 1.0;
    config.mss.enable = true;
    updates.deliver(&manager, &config, timeout).await;
    fail.send(()).unwrap();

    let (retry, finish) = tokio::time::timeout(timeout, started.recv()).await.unwrap().unwrap();
    assert_eq!(retry, config);
    finish.send(()).unwrap();
    tokio::time::timeout(timeout, manager.stop_all()).await.unwrap();
    assert!(started.try_recv().is_err());
}

#[tokio::test]
async fn failed_dataplane_replaces_both_wan_status_views() {
    use landscape_common::wan_link::{
        WanLinkRuntimeStatusStore, WanLinkState, WanLinkStatus, WanLinkStatusStore,
    };

    let id = Uuid::new_v4();
    let statuses: WanLinkStatusStore = Arc::default();
    statuses.write().await.insert(
        id,
        WanLinkStatus {
            state: WanLinkState::Running,
            session: ServiceStatus::Running,
            nat4: ServiceStatus::Running,
            ..Default::default()
        },
    );
    let runtime = WanLinkRuntimeStatusStore::default();
    runtime.install(id, Arc::default());

    super::record_dataplane_failure(id, &statuses, &runtime).await;
    let statuses = statuses.read().await;
    assert_eq!(statuses[&id].state, WanLinkState::Failed);
    assert_eq!(statuses[&id].session, ServiceStatus::Failed);
    assert_eq!(statuses[&id].nat4, ServiceStatus::Stop);
    assert!(runtime.get(&id).is_none());
}

#[test]
fn pd_toggle_changes_active_and_restarts_v4() {
    // Ethernet, v4 disabled, PD enabled -> active (lease-less anchor).
    let applied: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "pd": { "enable": true, "mac": "00:00:00:00:00:00", "expected_pd_len": 60 }
    }))
    .unwrap();
    let new: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "pd": { "enable": false, "mac": "00:00:00:00:00:00", "expected_pd_len": 60 }
    }))
    .unwrap();

    assert!(applied.active());
    assert!(!new.active());

    // pd.enable off must restart v4 so the lease-less anchor is dropped.
    let tags = config_change_tags(&applied, &new);
    assert!(tags.contains(&SectionTag::V4));
    assert!(tags.contains(&SectionTag::Pd));
}

#[test]
fn pd_default_router_toggle_restarts_pd_only() {
    let applied: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "pd": {
            "enable": true,
            "default_router": true,
            "mac": "00:00:00:00:00:00",
            "expected_pd_len": 60
        }
    }))
    .unwrap();
    let new: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "pd": {
            "enable": true,
            "default_router": false,
            "mac": "00:00:00:00:00:00",
            "expected_pd_len": 60
        }
    }))
    .unwrap();

    assert!(applied.active() && new.active());
    let tags = config_change_tags(&applied, &new);
    assert!(tags.contains(&SectionTag::Pd));
    assert!(!tags.contains(&SectionTag::V4));
}

#[test]
fn pppd_disable_is_inactive_and_restarts_v4() {
    let applied: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "kind": {
            "t": "pppd",
            "ppp_iface_name": "ppp0",
            "peer_id": "u",
            "password": "p",
            "ac": null,
            "plugin": "rp_pppoe"
        },
        "v4": { "enable": true, "model": { "t": "ipcp", "default_router": true } }
    }))
    .unwrap();
    let new: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "kind": {
            "t": "pppd",
            "ppp_iface_name": "ppp0",
            "peer_id": "u",
            "password": "p",
            "ac": null,
            "plugin": "rp_pppoe"
        },
        "v4": { "enable": false, "model": { "t": "ipcp", "default_router": true } }
    }))
    .unwrap();

    // A pppd link with v4 (and no PD) disabled is inactive: the session must be
    // torn down, not redialed.
    assert!(applied.active());
    assert!(!new.active());
    assert!(config_change_tags(&applied, &new).contains(&SectionTag::V4));
}

#[test]
fn pppd_pd_alone_is_inactive() {
    // A pppd link whose service switch (v4) is off stays inactive even with PD
    // enabled: PD cannot bring the PPP session up on its own.
    let link: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "kind": {
            "t": "pppd",
            "ppp_iface_name": "ppp0",
            "peer_id": "u",
            "password": "p",
            "ac": null,
            "plugin": "rp_pppoe"
        },
        "v4": { "enable": false, "model": { "t": "nothing" } },
        "pd": { "enable": true, "mac": "00:00:00:00:00:00", "expected_pd_len": 60 }
    }))
    .unwrap();

    assert!(!link.active());

    // The same shape on an ethernet link is active (V6-only anchor).
    let eth: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "v4": { "enable": false, "model": { "t": "nothing" } },
        "pd": { "enable": true, "mac": "00:00:00:00:00:00", "expected_pd_len": 60 }
    }))
    .unwrap();
    assert!(eth.active());
}

#[test]
fn normalized_nat_defaults_do_not_restart() {
    let applied: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "nat": { "enable": true }
    }))
    .unwrap();
    let new: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "nat": {
            "enable": true,
            "tcp_range": { "start": 32768, "end": 65535 },
            "udp_range": null,
            "icmp_in_range": null
        }
    }))
    .unwrap();

    // `None` and "explicit default" resolve to the same NatConfig.
    let tags = config_change_tags(&applied, &new);
    assert!(!tags.contains(&SectionTag::Nat4));
    assert!(!tags.contains(&SectionTag::V4));
}

#[test]
fn link_default_intents_tracks_active_v4_and_pd_default_router() {
    let disabled_primary: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "enp1s0",
        "kind": { "t": "pppoe_native", "username": "u", "password": "p", "requested_mru": 1492 },
        "v4": { "enable": false, "model": { "t": "ipcp", "default_router": true } },
        "pd": { "enable": false, "default_router": true, "mac": "02:00:00:00:00:01", "expected_pd_len": 60 }
    }))
    .unwrap();
    assert_eq!(link_default_intents(&disabled_primary), (false, false));

    let active_primary: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0001",
        "attach_iface_name": "enp1s0.105",
        "kind": { "t": "pppoe_native", "username": "u", "password": "p", "requested_mru": 1492 },
        "v4": { "enable": true, "model": { "t": "ipcp", "default_router": true } },
        "pd": { "enable": true, "default_router": true, "mac": "02:00:00:00:00:01", "expected_pd_len": 60 }
    }))
    .unwrap();
    assert_eq!(link_default_intents(&active_primary), (true, true));

    let active_secondary: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0002",
        "attach_iface_name": "enp1s0.101",
        "kind": { "t": "pppoe_native", "username": "u", "password": "p", "requested_mru": 1492 },
        "v4": { "enable": true, "model": { "t": "ipcp", "default_router": false } },
        "pd": { "enable": true, "default_router": false, "mac": "02:00:00:00:00:02", "expected_pd_len": 60 }
    }))
    .unwrap();
    assert_eq!(link_default_intents(&active_secondary), (false, false));

    let v4_default_only: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0003",
        "attach_iface_name": "enp1s0.101",
        "kind": { "t": "pppoe_native", "username": "u", "password": "p", "requested_mru": 1492 },
        "v4": { "enable": true, "model": { "t": "ipcp", "default_router": true } },
        "pd": { "enable": true, "default_router": false, "mac": "02:00:00:00:00:03", "expected_pd_len": 60 }
    }))
    .unwrap();
    assert_eq!(link_default_intents(&v4_default_only), (true, false));

    let v6_only_eth: WanLinkConfig = serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0004",
        "attach_iface_name": "eth0",
        "v4": { "enable": false, "model": { "t": "nothing" } },
        "pd": { "enable": true, "default_router": true, "mac": "02:00:00:00:00:04", "expected_pd_len": 60 }
    }))
    .unwrap();
    assert_eq!(link_default_intents(&v6_only_eth), (false, true));
}

fn board() -> WanLinkStatusHandle {
    WanLinkStatusHandle::new(Uuid::new_v4(), Arc::default(), true)
}

fn lease(ip: [u8; 4]) -> WanV4Lease {
    WanV4Lease::new(1, std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
}

fn v6_prefix() -> landscape_common::wan_link::WanV6Prefix {
    landscape_common::wan_link::WanV6Prefix {
        prefix_ip: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0),
        prefix_len: 56,
    }
}

fn v6_addr() -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0x8000, 0, 0, 0x1234)
}

fn counting_runner(starts: Arc<AtomicUsize>) -> SectionRunner {
    Arc::new(move |_iface, _cfg, run_status| {
        let starts = starts.clone();
        Box::pin(async move {
            starts.fetch_add(1, Ordering::SeqCst);
            run_status.just_change_status(ServiceStatus::Running);
            run_status.stop_token().cancelled().await;
            run_status.just_change_status(ServiceStatus::Stop);
        })
    })
}

fn failing_runner(attempts: Arc<AtomicUsize>) -> SectionRunner {
    Arc::new(move |_iface, _cfg, _run_status| {
        let attempts = attempts.clone();
        Box::pin(async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            // Return immediately without reporting Running (a dead run).
        })
    })
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("condition not satisfied in time");
}

#[tokio::test]
async fn session_scope_reattaches_on_reanchor_not_lease_change() {
    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);

    let (link_state, state_rx) = LinkStateHandle::new(None);
    let (_cfg_tx, cfg_rx) = watch::channel(link_config(true));
    let (_reconfig_tx, reconfig_rx) = broadcast::channel(8);

    let starts = Arc::new(AtomicUsize::new(0));
    let handle = tokio::spawn(run_dependent_section(
        link_status.clone(),
        board(),
        state_rx,
        cfg_rx,
        reconfig_rx,
        SectionTag::Nat4,
        SectionKind::Nat4,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        |state| state.is_up(),
        SectionScope::Session,
        counting_runner(starts.clone()),
        Duration::from_millis(10),
    ));

    // Session down: the section must not attach.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

    // Lease change on the same anchor: a Session-scoped section keeps running.
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 3])));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    // Re-anchor to a different iface (epoch bump): detach + re-attach.
    link_state.session_up(SessionIface::new(2, "eth1", None), Some(lease([10, 0, 0, 3])));
    wait_until(|| starts.load(Ordering::SeqCst) == 2).await;

    link_state.session_down();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 2);

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor did not stop")
        .unwrap();
}

#[tokio::test]
async fn nat_requires_a_v4_lease() {
    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);

    let (link_state, state_rx) = LinkStateHandle::new(None);
    let (_cfg_tx, cfg_rx) = watch::channel(link_config(true));
    let (_reconfig_tx, reconfig_rx) = broadcast::channel(8);

    let starts = Arc::new(AtomicUsize::new(0));
    let handle = tokio::spawn(run_dependent_section(
        link_status.clone(),
        board(),
        state_rx,
        cfg_rx,
        reconfig_rx,
        SectionTag::Nat4,
        SectionKind::Nat4,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        // NAT readiness: a v4 lease is required.
        |state| state.has_v4_lease(),
        SectionScope::SessionAndLease,
        counting_runner(starts.clone()),
        Duration::from_millis(10),
    ));

    // Up without a lease (PD-only ethernet / no-v4 anchor): must not attach.
    link_state.session_up(SessionIface::new(1, "eth0", None), None);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

    // The lease address is baked into the nat4 objects: a change re-attaches.
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 5])));
    wait_until(|| starts.load(Ordering::SeqCst) == 2).await;

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor did not stop")
        .unwrap();
}

#[tokio::test]
async fn nat6_requires_a_v6_prefix() {
    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);

    let (link_state, state_rx) = LinkStateHandle::new(None);
    let (_cfg_tx, cfg_rx) = watch::channel(link_config(true));
    let (_reconfig_tx, reconfig_rx) = broadcast::channel(8);

    let starts = Arc::new(AtomicUsize::new(0));
    let handle = tokio::spawn(run_dependent_section(
        link_status.clone(),
        board(),
        state_rx,
        cfg_rx,
        reconfig_rx,
        SectionTag::Nat6,
        SectionKind::Nat6,
        "wan.link.test.nat6",
        |cfg| cfg.nat.enable,
        // nat6 readiness: a WAN v6 prefix bound by the pd section is required.
        |state| state.has_v6_prefix(),
        SectionScope::Session,
        counting_runner(starts.clone()),
        Duration::from_millis(10),
    ));

    // A v4 lease alone (dual-stack without PD) must not start nat6.
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    // The pd section publishing a bound prefix starts nat6.
    link_state.set_v6_prefix(v6_prefix(), Some(v6_addr()));
    wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

    // Prefix expiry keeps nat6 attached; the pd re-bind restores it in place.
    link_state.clear_v6_prefix();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 1);

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor did not stop")
        .unwrap();
}

#[tokio::test]
async fn dead_section_run_is_retried_after_backoff() {
    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);

    let (link_state, state_rx) = LinkStateHandle::new(None);
    let (_cfg_tx, cfg_rx) = watch::channel(link_config(true));
    let (_reconfig_tx, reconfig_rx) = broadcast::channel(8);

    let attempts = Arc::new(AtomicUsize::new(0));
    let handle = tokio::spawn(run_dependent_section(
        link_status.clone(),
        board(),
        state_rx,
        cfg_rx,
        reconfig_rx,
        SectionTag::Nat4,
        SectionKind::Nat4,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        |state| state.is_up(),
        SectionScope::Session,
        failing_runner(attempts.clone()),
        Duration::from_millis(10),
    ));

    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    // The runner returns immediately each time; the supervisor must retry
    // after the backoff rather than giving up.
    wait_until(|| attempts.load(Ordering::SeqCst) >= 3).await;

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor did not stop")
        .unwrap();
}

#[tokio::test]
async fn health_check_runner_judges_and_cleans_up() {
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicBool;

    use landscape_common::wan_link::WanLinkHealthState;

    use super::health_check;
    use super::probe::{FakeProbe, WanHealthProbe};

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();
    let mut events = route_service.subscribe_health_events();

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));

    let up = Arc::new(AtomicBool::new(false));
    let up_for_probe = up.clone();
    let probe: Arc<dyn WanHealthProbe> = Arc::new(FakeProbe(move |_target| {
        Ok(up_for_probe.load(Ordering::SeqCst).then(|| Duration::from_millis(5)))
    }));

    let config = health_config(vec![Ipv4Addr::new(1, 1, 1, 1)]);

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        3,
        SessionIface::new(1, "eth0", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
        runtime_slot(),
    ));

    // Round 0 is warmup-tolerated, round 1 fails with threshold 1.
    wait_health(&route_service, link_id, WanLinkHealthState::Unhealthy).await;
    assert!(events.try_recv().is_ok(), "Unknown -> Unhealthy flip broadcast");

    up.store(true, Ordering::SeqCst);
    wait_health(&route_service, link_id, WanLinkHealthState::Healthy).await;

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("runner did not stop")
        .unwrap();
    assert!(route_service.get_link_health(link_id).await.is_none(), "exit clears the entry");
    assert_eq!(link_status.current(), ServiceStatus::Stop);
}

#[tokio::test]
async fn health_check_persistently_blind_rounds_fail_the_section() {
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;

    use super::health_check;
    use super::probe::{FakeProbe, ProbeError, WanHealthProbe};

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();
    let mut events = route_service.subscribe_health_events();

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));

    let probe: Arc<dyn WanHealthProbe> = Arc::new(FakeProbe(|_target| {
        Err(ProbeError::Socket(std::io::Error::from(ErrorKind::PermissionDenied)))
    }));
    let config = health_config(vec![Ipv4Addr::new(1, 1, 1, 1)]);

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        3,
        SessionIface::new(1, "eth0", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
        runtime_slot(),
    ));

    wait_status(&link_status, ServiceStatus::Failed).await;
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("runner did not exit")
        .unwrap();
    assert!(route_service.get_link_health(link_id).await.is_none(), "exit clears the entry");
    assert!(events.try_recv().is_err(), "a local error must never produce a health verdict");
    assert_eq!(
        route_service.get_link_healths().await.len(),
        0,
        "no Unknown entry lingers after the clear"
    );
}

#[tokio::test]
async fn health_check_local_error_target_carries_no_link_evidence() {
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;

    use landscape_common::wan_link::WanLinkHealthState;

    use super::health_check;
    use super::probe::{FakeProbe, ProbeError, WanHealthProbe};

    let errored_target = Ipv4Addr::new(1, 1, 1, 1);
    let failing_target = Ipv4Addr::new(2, 2, 2, 2);

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));

    let probe: Arc<dyn WanHealthProbe> = Arc::new(FakeProbe(move |target| {
        if target == errored_target {
            Err(ProbeError::Socket(std::io::Error::from(ErrorKind::PermissionDenied)))
        } else {
            Ok(None)
        }
    }));
    let config = health_config(vec![errored_target, failing_target]);

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        3,
        SessionIface::new(1, "eth0", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
        runtime_slot(),
    ));

    wait_health(&route_service, link_id, WanLinkHealthState::Unhealthy).await;
    let info = route_service.get_link_health(link_id).await.expect("entry exists");
    assert_eq!(info.targets.len(), 1, "the errored target is not part of the round");
    assert_eq!(info.targets[0].target, failing_target);
    assert_eq!(link_status.current(), ServiceStatus::Running, "mixed rounds keep running");

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("runner did not stop")
        .unwrap();
}

#[tokio::test]
async fn health_check_local_error_target_does_not_block_recovery() {
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;

    use landscape_common::wan_link::WanLinkHealthState;

    use super::health_check;
    use super::probe::{FakeProbe, ProbeError, WanHealthProbe};

    let errored_target = Ipv4Addr::new(1, 1, 1, 1);
    let healthy_target = Ipv4Addr::new(2, 2, 2, 2);

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));

    let probe: Arc<dyn WanHealthProbe> = Arc::new(FakeProbe(move |target| {
        if target == errored_target {
            Err(ProbeError::Socket(std::io::Error::from(ErrorKind::PermissionDenied)))
        } else {
            Ok(Some(Duration::from_millis(5)))
        }
    }));
    let config = health_config(vec![errored_target, healthy_target]);

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        3,
        SessionIface::new(1, "eth0", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
        runtime_slot(),
    ));

    wait_health(&route_service, link_id, WanLinkHealthState::Healthy).await;
    let info = route_service.get_link_health(link_id).await.expect("entry exists");
    assert_eq!(info.targets.len(), 1, "the errored target is not part of the round");
    assert_eq!(info.targets[0].target, healthy_target);
    assert_eq!(info.consecutive_failures, 0);
    assert_eq!(link_status.current(), ServiceStatus::Running);

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("runner did not stop")
        .unwrap();
}

#[tokio::test]
async fn health_check_local_error_target_does_not_wedge_full_reliability() {
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;

    use landscape_common::wan_link::WanLinkHealthState;

    use super::health_check;
    use super::probe::{FakeProbe, ProbeError, WanHealthProbe};

    let errored_target = Ipv4Addr::new(1, 1, 1, 1);
    let healthy_target = Ipv4Addr::new(2, 2, 2, 2);

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));

    let probe: Arc<dyn WanHealthProbe> = Arc::new(FakeProbe(move |target| {
        if target == errored_target {
            Err(ProbeError::Socket(std::io::Error::from(ErrorKind::PermissionDenied)))
        } else {
            Ok(Some(Duration::from_millis(5)))
        }
    }));
    // reliability equals the configured target count: without the cap a
    // single locally errored target would make every round fail forever.
    let mut config = health_config(vec![errored_target, healthy_target]);
    config.reliability = 2;

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        3,
        SessionIface::new(1, "eth0", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
        runtime_slot(),
    ));

    wait_health(&route_service, link_id, WanLinkHealthState::Healthy).await;
    let info = route_service.get_link_health(link_id).await.expect("entry exists");
    assert_eq!(info.targets.len(), 1, "the errored target is not part of the round");
    assert_eq!(info.targets[0].target, healthy_target);
    assert_eq!(info.consecutive_failures, 0);
    assert_eq!(link_status.current(), ServiceStatus::Running);

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("runner did not stop")
        .unwrap();
}

#[tokio::test]
async fn health_check_runner_forwards_chain_id_dev_and_src_to_probe() {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use landscape_common::wan_link::WanLinkHealthState;

    use super::health_check;
    use super::probe::{ProbeError, WanHealthProbe};

    #[derive(Debug, PartialEq, Eq)]
    struct ProbeCall {
        dev: String,
        src: Ipv4Addr,
        chain_id: u16,
        target: Ipv4Addr,
    }

    struct CaptureProbe {
        seen: Arc<Mutex<Vec<ProbeCall>>>,
    }

    #[async_trait::async_trait]
    impl WanHealthProbe for CaptureProbe {
        async fn ping_v4(
            &self,
            dev: &str,
            src: Ipv4Addr,
            chain_id: u16,
            target: Ipv4Addr,
            _timeout: Duration,
        ) -> Result<Option<Duration>, ProbeError> {
            self.seen.lock().unwrap().push(ProbeCall {
                dev: dev.to_string(),
                src,
                chain_id,
                target,
            });
            Ok(Some(Duration::from_millis(4)))
        }
    }

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();
    let chain_id = 3u16;
    let src = Ipv4Addr::new(100, 65, 247, 59);
    let target = Ipv4Addr::new(223, 5, 5, 5);

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state
        .session_up(SessionIface::new(37, "enp1s0.101", None), Some(WanV4Lease::new(37, src)));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let probe: Arc<dyn WanHealthProbe> = Arc::new(CaptureProbe { seen: seen.clone() });
    let config = health_config(vec![target]);

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        chain_id,
        SessionIface::new(37, "enp1s0.101", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
        runtime_slot(),
    ));

    wait_health(&route_service, link_id, WanLinkHealthState::Healthy).await;
    {
        let calls = seen.lock().unwrap();
        let expected = ProbeCall {
            dev: "enp1s0.101".to_string(),
            src,
            chain_id,
            target,
        };
        assert!(!calls.is_empty(), "probe must have been invoked");
        assert!(calls.iter().all(|c| c == &expected), "unexpected probe arguments: {calls:?}");
    }

    link_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("runner did not stop")
        .unwrap();
}

fn runtime_slot() -> Arc<ArcSwap<HealthCheckRuntime>> {
    Arc::new(ArcSwap::from_pointee(HealthCheckRuntime::Idle))
}

fn health_config(
    targets: Vec<std::net::Ipv4Addr>,
) -> landscape_common::wan_link::RuntimeWanLinkHealthCheckConfig {
    landscape_common::wan_link::RuntimeWanLinkHealthCheckConfig {
        enable: true,
        probe: landscape_common::wan_link::RuntimeWanHealthProbe::Icmp {
            targets,
            probe_gateway: false,
        },
        interval_secs: 1,
        timeout_ms: 100,
        failure_threshold: 1,
        recovery_threshold: 1,
        reliability: 1,
    }
}

async fn wait_health(
    route_service: &landscape_core::route::IpRouteService,
    link_id: Uuid,
    want: landscape_common::wan_link::WanLinkHealthState,
) {
    for _ in 0..900 {
        if route_service.get_link_health(link_id).await.is_some_and(|info| info.state == want) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("health state did not reach {want:?} in time");
}

async fn wait_status(handle: &ServiceHandle, want: ServiceStatus) {
    for _ in 0..2000 {
        if handle.current() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("section status did not reach {want:?} in time");
}
