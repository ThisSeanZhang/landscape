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

use super::{SectionRunner, SectionScope, SectionTag, config_change_tags, run_dependent_section};

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
    assert!(!tags.contains(&SectionTag::Nat4));
    assert!(!tags.contains(&SectionTag::V4));
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
        socket_mark: 0,
        enable: true,
        ipv4_enabled: true,
        ipv6_enabled: false,
        ipv4_probe_enabled: true,
        ipv6_probe_enabled: true,
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

#[test]
fn health_runtime_reports_probe_source_and_missing_enabled_family() {
    use landscape_common::wan_link::{HealthEvaluator, TargetProbe, WanLinkHealthState};
    let mut cfg = health_config(vec![]);
    cfg.ipv6_enabled = true;
    let mut evaluator = HealthEvaluator::new(Uuid::new_v4(), 1, 1, 1);
    evaluator.apply_round(&[TargetProbe {
        target: "192.0.2.1".parse().unwrap(),
        rtt: Some(Duration::from_millis(7)),
    }]);
    let info = Some(evaluator.info());
    let own_v4 = super::health_check::runtime_snapshot(&cfg, info, None, vec![]);
    assert!(matches!(own_v4, HealthCheckRuntime::Running {
        state: WanLinkHealthState::Unknown, ipv6: Some(ref v6), ..
    } if v6.probe_enabled && v6.state == WanLinkHealthState::Unknown));

    cfg.ipv6_probe_enabled = false;
    let following_v6 = super::health_check::runtime_snapshot(&cfg, info, None, vec![]);
    assert!(matches!(following_v6, HealthCheckRuntime::Running {
        state: WanLinkHealthState::Healthy, ipv6: Some(ref v6), ..
    } if !v6.probe_enabled && v6.state == WanLinkHealthState::Healthy && v6.rtt_ewma_ms == Some(7.0)));

    cfg.ipv4_probe_enabled = false;
    cfg.ipv6_probe_enabled = true;
    let following_v4 = super::health_check::runtime_snapshot(&cfg, None, info, vec![]);
    assert!(matches!(following_v4, HealthCheckRuntime::Running {
        state: WanLinkHealthState::Healthy, ipv4: Some(ref v4), ..
    } if !v4.probe_enabled && v4.state == WanLinkHealthState::Healthy));

    cfg.ipv4_probe_enabled = true;
    cfg.ipv6_enabled = false;
    let ipv4_only = super::health_check::runtime_snapshot(&cfg, info, None, vec![]);
    assert!(matches!(
        ipv4_only,
        HealthCheckRuntime::Running { state: WanLinkHealthState::Healthy, ipv6: None, .. }
    ));
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

#[test]
fn probe_family_toggle_only_restarts_health_section() {
    let old = link_config(false);
    let mut new = old.clone();
    new.health_check.ipv6_probe_enabled = false;
    assert_eq!(config_change_tags(&old, &new), vec![SectionTag::HealthCheck]);
}

#[tokio::test]
async fn disabled_probe_family_inherits_faults_recovery_and_unknown_in_both_directions() {
    use landscape_common::wan_link::{HealthEvaluator, WanLinkHealthState};
    let routes = landscape_core::route::test_used_ip_route();
    let id = Uuid::new_v4();
    for source_v6 in [false, true] {
        let mut cfg = health_config(vec!["223.5.5.5".parse().unwrap()]);
        cfg.ipv4_probe_enabled = !source_v6;
        cfg.ipv6_probe_enabled = source_v6;
        for state in [
            WanLinkHealthState::Healthy,
            WanLinkHealthState::Unhealthy,
            WanLinkHealthState::Healthy,
            WanLinkHealthState::Unknown,
        ] {
            let mut info = HealthEvaluator::new(id, 1, 1, 1).info().clone();
            info.state = state;
            routes.update_link_health_for_family(info.clone(), source_v6).await;
            super::health_check::sync_followed_family(&routes, id, &cfg).await;
            assert_eq!(routes.get_link_health_for_family(id, !source_v6).await, Some(info));
        }
        routes.clear_link_health_for_family(id, source_v6).await;
        super::health_check::sync_followed_family(&routes, id, &cfg).await;
        assert!(routes.get_link_health_for_family(id, !source_v6).await.is_none());
    }
    let cfg = health_config(vec![]); // both switches on: independent verdicts
    let mut info = HealthEvaluator::new(id, 1, 1, 1).info().clone();
    info.state = WanLinkHealthState::Healthy;
    routes.update_link_health(info).await;
    super::health_check::sync_followed_family(&routes, id, &cfg).await;
    assert!(routes.get_link_health_for_family(id, true).await.is_none());
}

#[tokio::test]
async fn legacy_probe_runner_publishes_and_clears_the_disabled_family() {
    use super::probe::{FakeProbe, WanHealthProbe};
    use landscape_common::wan_link::WanLinkHealthState;
    let routes = landscape_core::route::test_used_ip_route();
    let id = Uuid::new_v4();
    let (state, _rx) = LinkStateHandle::new(None);
    state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
    let probe: Arc<dyn WanHealthProbe> =
        Arc::new(FakeProbe(|_| Ok(Some(Duration::from_millis(1)))));
    let mut cfg = health_config(vec!["223.5.5.5".parse().unwrap()]);
    cfg.ipv6_probe_enabled = false;
    let status = ServiceHandle::new();
    status.just_change_status(ServiceStatus::Staring);
    let runner = tokio::spawn(super::health_check::run(
        id,
        SessionIface::new(1, "eth0", None),
        state,
        cfg,
        status.clone(),
        probe,
        routes.clone(),
        runtime_slot(),
    ));
    wait_health(&routes, id, WanLinkHealthState::Healthy).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if routes
                .get_link_health_for_family(id, true)
                .await
                .is_some_and(|h| h.state == WanLinkHealthState::Healthy)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), runner).await.unwrap().unwrap();
    assert!(routes.get_link_health_for_family(id, true).await.is_none());
}

/// A controlled dual-stack probe lets the real section supervisor and multi
/// runner process lease/prefix changes without touching the host network.
struct ControlledProbe {
    requests: tokio::sync::mpsc::UnboundedSender<ProbeRequest>,
    run_id: usize,
}
#[derive(Debug)]
struct ProbeRequest {
    dev: String,
    src: std::net::IpAddr,
    mark: u32,
    run_id: usize,
    reply: tokio::sync::oneshot::Sender<Result<Option<Duration>, super::probe::ProbeError>>,
}
#[async_trait::async_trait]
impl super::probe::WanHealthProbe for ControlledProbe {
    async fn probe_target(
        &self,
        dev: &str,
        src: std::net::IpAddr,
        _target: &landscape_common::wan_link::WanProbeTarget,
        _timeout: Duration,
        mark: u32,
    ) -> Result<Option<Duration>, super::probe::ProbeError> {
        let (reply, result) = tokio::sync::oneshot::channel();
        self.requests
            .send(ProbeRequest {
                dev: dev.into(),
                src,
                mark,
                run_id: self.run_id,
                reply,
            })
            .unwrap();
        result.await.unwrap_or(Ok(None))
    }

    async fn ping_v4(
        &self,
        _dev: &str,
        _src: std::net::Ipv4Addr,
        _target: std::net::Ipv4Addr,
        _timeout: Duration,
    ) -> Result<Option<Duration>, super::probe::ProbeError> {
        panic!("grouped probes must use the dual-stack injection point")
    }
}

#[tokio::test]
async fn running_health_rebinds_on_ipv4_renewal_and_ipv6_pd_address_change() {
    use landscape_common::wan_link::{
        RuntimeWanLinkConfig, WanHealthProbeConfig, WanLinkHealthState, WanProbeGroup,
        WanProbeTarget, WanV6Prefix,
    };
    use std::net::IpAddr;
    for ipv6_change in [false, true] {
        let routes = landscape_core::route::test_used_ip_route();
        let mut config = link_config(false);
        config.link_chain_id = 7;
        config.v4.enable = true;
        config.pd.enable = true;
        config.health_check.enable = true;
        config.health_check.interval_secs = Some(600);
        config.health_check.probe = WanHealthProbeConfig::Multi {
            groups: ["192.0.2.1", "2001:db8::1"]
                .into_iter()
                .map(|address| WanProbeGroup {
                    name: address.into(),
                    quorum: 1,
                    targets: vec![WanProbeTarget::Icmp { address: address.parse().unwrap() }],
                })
                .collect(),
        };
        let id = config.id;
        let (state, state_rx) = LinkStateHandle::new(None);
        state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 2])));
        state.set_v6_prefix(v6_prefix(), Some(v6_addr()));
        let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
        let starts = Arc::new(AtomicUsize::new(0));
        let runtime = runtime_slot();
        let runner: SectionRunner = {
            let routes = routes.clone();
            let state = state.clone();
            let starts = starts.clone();
            Arc::new(move |iface, config, status| {
                let routes = routes.clone();
                let state = state.clone();
                let runtime = runtime.clone();
                let run_id = starts.fetch_add(1, Ordering::SeqCst) + 1;
                let probe: Arc<dyn super::probe::WanHealthProbe> =
                    Arc::new(ControlledProbe { requests: requests.clone(), run_id });
                Box::pin(super::health_check::run(
                    id,
                    iface,
                    state,
                    RuntimeWanLinkConfig::from_config(&config).health_check,
                    status,
                    probe,
                    routes,
                    runtime,
                ))
            })
        };
        let (_cfg_tx, cfg_rx) = watch::channel(config);
        let (_reconfig_tx, reconfig_rx) = broadcast::channel(8);
        let link_status = ServiceHandle::new();
        // Match the production link lifecycle: Stop -> Running is rejected,
        // and would leave the later Stopping transition unable to cancel.
        link_status.just_change_status(ServiceStatus::Staring);
        link_status.just_change_status(ServiceStatus::Running);
        assert!(link_status.is_running());
        let supervisor = tokio::spawn(run_dependent_section(
            link_status.clone(),
            board(),
            state_rx,
            cfg_rx,
            reconfig_rx,
            SectionTag::HealthCheck,
            SectionKind::HealthCheck,
            "health-lease-regression",
            |cfg| cfg.health_check.enable,
            |state| state.has_v4_lease() || state.has_v6_prefix(),
            SectionScope::SessionAndLease,
            runner,
            Duration::from_millis(1),
        ));
        for _ in 0..2 {
            let request = tokio::time::timeout(Duration::from_secs(2), received.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.dev, "eth0");
            assert_eq!(request.mark, 0x0200_0007);
            request.reply.send(Ok(Some(Duration::from_millis(1)))).unwrap();
        }
        let wait_healthy = || async {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let v4 = routes.get_link_health_for_family(id, false).await;
                    let v6 = routes.get_link_health_for_family(id, true).await;
                    if [v4, v6]
                        .iter()
                        .all(|h| h.as_ref().is_some_and(|h| h.state == WanLinkHealthState::Healthy))
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        };
        wait_healthy().await;
        let new_source: IpAddr = if ipv6_change {
            let address = "2001:db8:2::1234".parse().unwrap();
            state.set_v6_prefix(
                WanV6Prefix {
                    prefix_ip: "2001:db8:2::".parse().unwrap(),
                    prefix_len: 56,
                },
                Some(address),
            );
            address.into()
        } else {
            state.session_up(SessionIface::new(1, "eth0", None), Some(lease([10, 0, 0, 3])));
            "10.0.0.3".parse().unwrap()
        };
        // Hold the new-source result pending: the old healthy verdict must
        // already have been removed, rather than surviving the lease change.
        let changed_request = loop {
            let request = tokio::time::timeout(Duration::from_secs(2), received.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.dev, "eth0");
            assert_eq!(request.mark, 0x0200_0007);
            if request.src == new_source && request.run_id == if ipv6_change { 1 } else { 2 } {
                break request;
            }
            let _ = request.reply.send(Ok(Some(Duration::from_millis(1))));
        };
        assert!(routes.get_link_health_for_family(id, ipv6_change).await.is_none());
        changed_request.reply.send(Ok(Some(Duration::from_millis(2)))).unwrap();
        // The unchanged family may still be queued behind the changed one.
        while let Ok(request) = received.try_recv() {
            let _ = request.reply.send(Ok(Some(Duration::from_millis(1))));
        }
        wait_healthy().await;
        assert_eq!(starts.load(Ordering::SeqCst), if ipv6_change { 1 } else { 2 });
        link_status.just_change_status(ServiceStatus::Stopping);
        assert!(link_status.stop_token().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap();
        assert!(routes.get_link_health_for_family(id, false).await.is_none());
        assert!(routes.get_link_health_for_family(id, true).await.is_none());
    }
}
