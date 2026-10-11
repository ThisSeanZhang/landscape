use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, watch};
use uuid::Uuid;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{
    HealthCheckRuntime, LinkStateHandle, SectionKind, SessionIface, WanLinkConfig,
    WanLinkStatusHandle, WanV4Lease,
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
