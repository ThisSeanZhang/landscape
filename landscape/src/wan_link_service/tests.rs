use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, watch};
use uuid::Uuid;

use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{
    LinkStateHandle, SectionKind, SessionIface, WanLinkConfig, WanLinkStatusHandle, WanV4Lease,
};

use super::{SectionRunner, SectionTag, config_change_tags, run_dependent_section};

fn link_config(nat_enable: bool) -> WanLinkConfig {
    serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "nat": { "enable": nat_enable }
    }))
    .unwrap()
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
    assert!(!tags.contains(&SectionTag::Nat));
    assert!(!tags.contains(&SectionTag::V4));
}

fn board() -> WanLinkStatusHandle {
    WanLinkStatusHandle::new(Uuid::new_v4(), Arc::default(), true)
}

fn lease(ip: [u8; 4]) -> WanV4Lease {
    WanV4Lease::new(1, std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
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
async fn dependent_waits_for_session_and_reattaches_on_epoch_change() {
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
        SectionTag::Nat,
        SectionKind::Nat,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        |state| state.is_up(),
        counting_runner(starts.clone()),
        Duration::from_millis(10),
    ));

    // Session down: the section must not attach.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

    // Session rebuilt (epoch bump): detach + re-attach.
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 3])));
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
        SectionTag::Nat,
        SectionKind::Nat,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        // NAT readiness: a v4 lease is required.
        |state| state.has_v4_lease(),
        counting_runner(starts.clone()),
        Duration::from_millis(10),
    ));

    // Up without a lease (PD-only ethernet / no-v4 anchor): must not attach.
    link_state.session_up(SessionIface::new(1, "eth0", None), None);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

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
        SectionTag::Nat,
        SectionKind::Nat,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        |state| state.is_up(),
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

    use landscape_common::wan_link::{
        RuntimeWanHealthProbe, RuntimeWanLinkHealthCheckConfig, WanLinkHealthState,
    };
    use landscape_core::route::IpRouteService;

    use super::health_check;
    use super::probe::{FakeProbe, WanHealthProbe};

    async fn wait_health(route_service: &IpRouteService, link_id: Uuid, want: WanLinkHealthState) {
        for _ in 0..900 {
            if route_service.get_link_health(link_id).await.is_some_and(|info| info.state == want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("health state did not reach {want:?} in time");
    }

    let route_service = landscape_core::route::test_used_ip_route();
    let link_id = Uuid::new_v4();
    let mut events = route_service.subscribe_health_events();

    let (link_state, _state_rx) = LinkStateHandle::new(None);
    link_state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));

    let up = Arc::new(AtomicBool::new(false));
    let up_for_probe = up.clone();
    let probe: Arc<dyn WanHealthProbe> = Arc::new(FakeProbe(move |_target| {
        up_for_probe.load(Ordering::SeqCst).then(|| Duration::from_millis(5))
    }));

    let config = RuntimeWanLinkHealthCheckConfig {
        enable: true,
        probe: RuntimeWanHealthProbe::Icmp {
            targets: vec![Ipv4Addr::new(1, 1, 1, 1)],
            probe_gateway: false,
        },
        interval_secs: 1,
        timeout_ms: 100,
        failure_threshold: 1,
        recovery_threshold: 1,
        reliability: 1,
    };

    let link_status = ServiceHandle::new();
    link_status.just_change_status(ServiceStatus::Staring);
    let handle = tokio::spawn(health_check::run(
        link_id,
        SessionIface::new(1, "eth0", None),
        link_state,
        config,
        link_status.clone(),
        probe,
        route_service.clone(),
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
