use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use landscape_common::net::MacAddr;
use landscape_common::service::WatchService;
use landscape_common::wan_service::ipv6_pd::IAPrefixMap;
use landscape_common::wan_service::link::dataplane::NoopWanLinkChainDataplane;
use landscape_common::wan_service::link::session::WanV4Lease;
use landscape_common::wan_service::link::{
    WanLinkConfig, WanLinkKindConfig, WanNatConfig, WanPdConfig, WanV4Config, WanV4Model,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::drivers::mocks::{
    test_iface, MockSectionRunner, MockSessionDriver, SessionBehavior, StaticIfaceLookup,
};
use super::drivers::{SectionTask, SessionDriver, SessionSpec};
use super::starter::{run_link_instance, WanLinkDeps};

const WAN0_MAC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 0x01);

fn link(nat_enable: bool) -> WanLinkConfig {
    WanLinkConfig {
        id: Uuid::new_v4(),
        name: "wan".to_string(),
        attach_iface_name: "wan0".to_string(),
        v4: WanV4Config {
            enable: true,
            model: WanV4Model::DhcpClient {
                hostname: None,
                default_router: true,
                custome_opts: vec![],
            },
        },
        nat: WanNatConfig { enable: nat_enable, ..Default::default() },
        ..Default::default()
    }
}

fn deps(session: Arc<dyn SessionDriver>, sections: Arc<MockSectionRunner>) -> Arc<WanLinkDeps> {
    Arc::new(WanLinkDeps {
        iface_lookup: Arc::new(StaticIfaceLookup(vec![test_iface("wan0", 5, Some(WAN0_MAC))])),
        session_driver: session,
        section_runner: sections,
        status_store: Arc::default(),
        prefix_map: IAPrefixMap::new(),
        chain_dp: Arc::new(NoopWanLinkChainDataplane),
    })
}

async fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..150 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

fn nat_count(sections: &MockSectionRunner) -> usize {
    sections
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, task)| matches!(task, SectionTask::Nat(_)))
        .count()
}

#[tokio::test]
async fn session_ready_starts_nat_and_config_edit_restarts_only_nat() {
    let session =
        Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop).with_lease(WanV4Lease {
            ifindex: 5,
            ip: Ipv4Addr::new(192, 0, 2, 10),
            gateway: Ipv4Addr::new(192, 0, 2, 1),
        }));
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = deps(session_driver, sections.clone());

    let status = WatchService::new();
    let (config_tx, config_rx) = mpsc::channel(4);
    let cfg = link(true);
    let id = cfg.id;

    let handle =
        tokio::spawn(run_link_instance(cfg.clone(), status.clone(), config_rx, deps.clone()));

    assert!(
        wait_for(|| nat_count(&sections) == 1).await,
        "NAT should start once the session is Ready"
    );
    assert_eq!(session.calls.lock().unwrap().len(), 1);

    // Edit only the NAT range: NAT restarts, the session is untouched.
    let mut edited = cfg.clone();
    edited.nat.tcp_range = Some(30000..40000);
    config_tx.send(edited).await.unwrap();
    assert!(
        wait_for(|| nat_count(&sections) == 2).await,
        "changing the NAT config must restart the NAT section"
    );
    assert_eq!(
        session.calls.lock().unwrap().len(),
        1,
        "a section edit must not restart the session"
    );

    status.wait_stop().await;
    let _ = handle.await;
    // Teardown leaves a terminal status for the link in the store.
    let final_state =
        deps.status_store.read().await.get(&id.to_string()).map(|status| status.state);
    assert_eq!(final_state, Some(landscape_common::wan_service::link::LinkState::Stop));
}

#[tokio::test]
async fn changing_the_session_model_restarts_the_session() {
    let session = Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop));
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = deps(session_driver, sections.clone());

    let status = WatchService::new();
    let (config_tx, config_rx) = mpsc::channel(4);
    let cfg = link(false);

    let handle = tokio::spawn(run_link_instance(cfg.clone(), status.clone(), config_rx, deps));

    assert!(wait_for(|| session.calls.lock().unwrap().len() == 1).await);

    // Switch the v4 acquisition model: the session key changes, so a new
    // session child is spawned.
    let mut edited = cfg.clone();
    edited.v4.model = WanV4Model::Static {
        ipv4: Some(Ipv4Addr::new(192, 0, 2, 20)),
        ipv4_mask: Some(24),
        ipv6: None,
        default_router: true,
        default_router_ip: Some(Ipv4Addr::new(192, 0, 2, 1)),
    };
    config_tx.send(edited).await.unwrap();
    assert!(
        wait_for(|| session.calls.lock().unwrap().len() == 2).await,
        "changing the session inputs must restart the session"
    );

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn inactive_link_stays_idle() {
    let session = Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop));
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = deps(session_driver, sections.clone());

    let status = WatchService::new();
    let (_config_tx, config_rx) = mpsc::channel(4);
    let mut cfg = link(true);
    cfg.v4.enable = false;
    let id = cfg.id;

    let handle = tokio::spawn(run_link_instance(cfg, status.clone(), config_rx, deps.clone()));

    assert!(
        wait_for(|| {
            deps.status_store
                .try_read()
                .ok()
                .and_then(|guard| guard.get(&id.to_string()).map(|s| s.state))
                .map(|state| state == landscape_common::wan_service::link::LinkState::Idle)
                .unwrap_or(false)
        })
        .await
    );

    assert_eq!(session.calls.lock().unwrap().len(), 0, "inactive link spawns no session");
    assert_eq!(sections.calls.lock().unwrap().len(), 0);

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn session_lost_stops_sections_and_recovery_restarts() {
    let lease = WanV4Lease {
        ifindex: 5,
        ip: Ipv4Addr::new(192, 0, 2, 10),
        gateway: Ipv4Addr::new(192, 0, 2, 1),
    };
    let (session, control) = MockSessionDriver::controlled(lease);
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = deps(session_driver, sections.clone());

    let status = WatchService::new();
    let (_config_tx, config_rx) = mpsc::channel(4);
    let handle = tokio::spawn(run_link_instance(link(true), status.clone(), config_rx, deps));

    assert!(wait_for(|| nat_count(&sections) == 1).await, "NAT starts on Ready");
    assert_eq!(session.calls.lock().unwrap().len(), 1);

    // Losing the session must tear the sections down.
    control.go_lost();
    assert!(wait_for(|| sections.stop_count("nat") == 1).await, "Lost must stop NAT");
    assert_eq!(nat_count(&sections), 1, "Lost must not respawn NAT");

    // Recovery must bring the sections back off the same session.
    control.go_ready(Some(lease));
    assert!(wait_for(|| nat_count(&sections) == 2).await, "recovery must restart NAT");
    assert_eq!(
        session.calls.lock().unwrap().len(),
        1,
        "Lost/recovery must not restart the session"
    );

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn lease_change_rebinds_nat_without_restarting_session() {
    let first = WanV4Lease {
        ifindex: 5,
        ip: Ipv4Addr::new(192, 0, 2, 10),
        gateway: Ipv4Addr::new(192, 0, 2, 1),
    };
    let second = WanV4Lease { ip: Ipv4Addr::new(192, 0, 2, 11), ..first };
    let (session, control) = MockSessionDriver::controlled(first);
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = deps(session_driver, sections.clone());

    let status = WatchService::new();
    let (_config_tx, config_rx) = mpsc::channel(4);
    let handle = tokio::spawn(run_link_instance(link(true), status.clone(), config_rx, deps));

    assert!(wait_for(|| nat_count(&sections) == 1).await);

    // A new lease on a still-Ready session re-attaches NAT only.
    control.go_ready(Some(second));
    assert!(wait_for(|| nat_count(&sections) == 2).await, "a new lease must re-attach NAT");
    assert_eq!(
        session.calls.lock().unwrap().len(),
        1,
        "a lease change must not restart the session"
    );

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn ethernet_pd_only_starts_pd_section_without_nat() {
    let session = Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop));
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = deps(session_driver, sections.clone());

    let status = WatchService::new();
    let (_config_tx, config_rx) = mpsc::channel(4);
    let cfg = WanLinkConfig {
        id: Uuid::new_v4(),
        name: "wan".to_string(),
        attach_iface_name: "wan0".to_string(),
        v4: WanV4Config { enable: false, ..Default::default() },
        pd: WanPdConfig { enable: true, mac: WAN0_MAC, ..Default::default() },
        nat: WanNatConfig { enable: true, ..Default::default() },
        ..Default::default()
    };

    let handle = tokio::spawn(run_link_instance(cfg, status.clone(), config_rx, deps.clone()));

    assert!(
        wait_for(|| {
            sections
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|(_, _, task)| matches!(task, SectionTask::Pd(_)))
        })
        .await,
        "PD-only ethernet must start the PD section off the synthesized anchor"
    );
    assert!(
        matches!(
            session.calls.lock().unwrap().first().map(|(_, _, spec)| spec),
            Some(SessionSpec::None)
        ),
        "PD-only ethernet must use the None session spec (no v4 acquisition)"
    );
    let pd_len = sections.calls.lock().unwrap().iter().find_map(|(_, _, task)| match task {
        SectionTask::Pd(pd) => Some(pd.expected_pd_len),
        _ => None,
    });
    assert_eq!(pd_len, Some(60), "unset expected_pd_len must default to 60");
    assert!(
        !sections
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, _, task)| matches!(task, SectionTask::Nat(_))),
        "PD-only ethernet has no v4 lease, so NAT must not start"
    );

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn changing_attach_iface_restarts_the_session() {
    let session =
        Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop).with_lease(WanV4Lease {
            ifindex: 5,
            ip: Ipv4Addr::new(192, 0, 2, 10),
            gateway: Ipv4Addr::new(192, 0, 2, 1),
        }));
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = Arc::new(WanLinkDeps {
        iface_lookup: Arc::new(StaticIfaceLookup(vec![
            test_iface("wan0", 5, Some(WAN0_MAC)),
            test_iface("wan1", 7, Some(WAN0_MAC)),
        ])),
        session_driver,
        section_runner: sections,
        status_store: Arc::default(),
        prefix_map: IAPrefixMap::new(),
        chain_dp: Arc::new(NoopWanLinkChainDataplane),
    });

    let status = WatchService::new();
    let (config_tx, config_rx) = mpsc::channel(4);
    let mut cfg = link(false);
    cfg.attach_iface_name = "wan0".to_string();

    let handle = tokio::spawn(run_link_instance(cfg.clone(), status.clone(), config_rx, deps));

    assert!(wait_for(|| session.calls.lock().unwrap().len() == 1).await);
    assert_eq!(session.calls.lock().unwrap()[0].1, "wan0");

    // Move the link to another iface: the session must be re-established there.
    let mut edited = cfg.clone();
    edited.attach_iface_name = "wan1".to_string();
    config_tx.send(edited).await.unwrap();

    assert!(
        wait_for(|| session.calls.lock().unwrap().len() == 2).await,
        "moving the link to another attach iface must restart the session"
    );
    assert_eq!(session.calls.lock().unwrap()[1].1, "wan1");

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn mac_less_attach_yields_invalid_session_without_sections() {
    let session = Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop));
    let sections = MockSectionRunner::new();
    let session_driver: Arc<dyn SessionDriver> = session.clone();
    let deps = Arc::new(WanLinkDeps {
        iface_lookup: Arc::new(StaticIfaceLookup(vec![test_iface("wan0", 5, None)])),
        session_driver,
        section_runner: sections.clone(),
        status_store: Arc::default(),
        prefix_map: IAPrefixMap::new(),
        chain_dp: Arc::new(NoopWanLinkChainDataplane),
    });

    let status = WatchService::new();
    let (_config_tx, config_rx) = mpsc::channel(4);
    let mut cfg = link(true);
    cfg.kind = WanLinkKindConfig::PppoeNative {
        username: "u".to_string(),
        password: "p".to_string(),
        requested_mru: None,
        ac_name: None,
        lcp_echo_interval: None,
        redial_backoff_base_secs: None,
    };
    cfg.v4 = WanV4Config {
        enable: true,
        model: WanV4Model::Ipcp { default_router: true },
    };

    let handle = tokio::spawn(run_link_instance(cfg, status.clone(), config_rx, deps));

    assert!(
        wait_for(|| {
            matches!(
                session.calls.lock().unwrap().first().map(|(_, _, spec)| spec),
                Some(SessionSpec::Invalid)
            )
        })
        .await,
        "a MAC-less PPPoE attach must resolve to Invalid"
    );
    assert!(
        sections.calls.lock().unwrap().is_empty(),
        "no section may start for an invalid session"
    );

    status.wait_stop().await;
    let _ = handle.await;
}

#[tokio::test]
async fn manager_allocates_then_freezes_link_chain_id() {
    use landscape_common::event::hub::EventHub;
    use landscape_database::provider::LandscapeDBServiceProvider;

    let hub = EventHub::new().spawn();
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let session = Arc::new(MockSessionDriver::new(SessionBehavior::RunUntilStop));
    let sections = MockSectionRunner::new();
    let manager = super::WanLinkServiceManagerService::with_deps(
        deps(session, sections),
        provider,
        hub.subscribe_iface(),
    )
    .await;

    // A brand-new link submits 0; the manager lets the insert path allocate 1.
    let mut cfg = link(false);
    cfg.v4.enable = false; // inactive: this test only checks persisted identity
    cfg.link_chain_id = 0;
    let id = cfg.id;
    manager.handle_service_config(cfg).await.unwrap();

    let stored = manager.list_links().await.into_iter().find(|l| l.id == id).unwrap();
    assert_eq!(stored.link_chain_id, 1, "first allocation must be 1");

    // Editing submits a bogus value; the manager forces the stored one back.
    let mut edited = stored.clone();
    edited.link_chain_id = 999;
    edited.name = "edited".to_string();
    manager.handle_service_config(edited).await.unwrap();

    let stored = manager.list_links().await.into_iter().find(|l| l.id == id).unwrap();
    assert_eq!(stored.link_chain_id, 1, "update must not change the chain id");
    assert_eq!(stored.name, "edited");
}
