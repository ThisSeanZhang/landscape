use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{broadcast, watch};

use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{LinkStateHandle, SessionIface, WanLinkConfig};

use super::{SectionRunner, SectionTag, run_dependent_section};

fn link_config(nat_enable: bool) -> WanLinkConfig {
    serde_json::from_value(serde_json::json!({
        "id": "0b6e4e88-0a85-4e1f-8e15-7d1d3d0d0000",
        "attach_iface_name": "eth0",
        "nat": { "enable": nat_enable }
    }))
    .unwrap()
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
    let starts_runner = starts.clone();
    let runner: SectionRunner = Arc::new(move |_iface, _cfg, run_status| {
        let starts = starts_runner.clone();
        Box::pin(async move {
            starts.fetch_add(1, Ordering::SeqCst);
            run_status.just_change_status(ServiceStatus::Running);
            run_status.stop_token().cancelled().await;
            run_status.just_change_status(ServiceStatus::Stop);
        })
    });

    let task_status = link_status.clone();
    let handle = tokio::spawn(run_dependent_section(
        link_status.clone(),
        state_rx,
        cfg_rx,
        reconfig_rx,
        SectionTag::Nat,
        "wan.link.test.nat",
        |cfg| cfg.nat.enable,
        runner,
    ));

    // Session down: the section must not attach.
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    link_state.session_up(SessionIface::new(1, "eth0", None));
    wait_until(|| starts.load(Ordering::SeqCst) == 1).await;

    link_state.session_up(
        SessionIface::new(1, "eth0", None).with_ip(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))),
    );
    wait_until(|| starts.load(Ordering::SeqCst) == 2).await;

    link_state.session_down();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(starts.load(Ordering::SeqCst), 2);

    task_status.just_change_status(ServiceStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor did not stop")
        .unwrap();
}
