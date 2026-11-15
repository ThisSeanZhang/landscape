//! Independent IPv4/IPv6 health rounds. All groups must meet their own quorum.
use super::probe::WanHealthProbe;
use crate::sys_service::route::IpRouteService;
use arc_swap::ArcSwap;
use futures::future::join_all;
use landscape_common::{
    service::{ServiceHandle, ServiceStatus},
    wan_link::{
        HealthCheckRuntime, HealthEvaluator, HealthProbeStatus, LinkStateHandle,
        RuntimeWanLinkHealthCheckConfig, SessionIface, TargetProbe, WanProbeGroup, swap_if_changed,
    },
};
use std::{net::IpAddr, sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
enum GroupVerdict {
    Healthy,
    Failed,
    Unknown,
}

fn group_verdict(successes: usize, errors: usize, quorum: u8) -> GroupVerdict {
    if successes >= usize::from(quorum) {
        GroupVerdict::Healthy
    } else if successes + errors >= usize::from(quorum) {
        GroupVerdict::Unknown
    } else {
        GroupVerdict::Failed
    }
}

struct FamilyState {
    source: Option<IpAddr>,
    evaluator: HealthEvaluator,
    blind: u8,
    probes: Vec<HealthProbeStatus>,
}

impl FamilyState {
    fn new(link_id: Uuid, cfg: &RuntimeWanLinkHealthCheckConfig) -> Self {
        Self {
            source: None,
            evaluator: HealthEvaluator::new(
                link_id,
                cfg.failure_threshold,
                cfg.recovery_threshold,
                1,
            ),
            blind: 0,
            probes: vec![],
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn round(
    family: &mut FamilyState,
    source: Option<IpAddr>,
    ipv6: bool,
    link_id: Uuid,
    iface: &SessionIface,
    groups: &[WanProbeGroup],
    cfg: &RuntimeWanLinkHealthCheckConfig,
    probe: &Arc<dyn WanHealthProbe>,
    routes: &IpRouteService,
) {
    if !(if ipv6 { cfg.ipv6_probe_enabled } else { cfg.ipv4_probe_enabled }) {
        return;
    }
    let groups: Vec<_> = groups
        .iter()
        .filter(|g| g.targets.first().is_some_and(|p| p.address().is_ipv6() == ipv6))
        .collect();
    if family.source != source || groups.is_empty() || source.is_none() {
        *family = FamilyState::new(link_id, cfg);
        family.source = source;
        routes.clear_link_health_for_family(link_id, ipv6).await;
    }
    let Some(src) = source.filter(|_| !groups.is_empty()) else { return };
    let timeout = Duration::from_millis(cfg.timeout_ms.into());
    let results = join_all(groups.iter().map(|group| async move {
        let results = join_all(group.targets.iter().map(|target| async move {
            let result =
                probe.probe_target(&iface.iface_name, src, target, timeout, cfg.socket_mark).await;
            (target.address(), result)
        }))
        .await;
        let successes = results.iter().filter(|(_, r)| matches!(r, Ok(Some(_)))).count();
        let errors = results.iter().filter(|(_, r)| r.is_err()).count();
        (group_verdict(successes, errors, group.quorum), results)
    }))
    .await;
    family.probes = results
        .iter()
        .flat_map(|(_, results)| {
            results.iter().map(|(target, result)| HealthProbeStatus {
                target: *target,
                rtt_ms: result.as_ref().ok().and_then(|r| r.map(|rtt| rtt.as_millis() as u64)),
            })
        })
        .collect();
    let failed = results.iter().any(|(verdict, _)| *verdict == GroupVerdict::Failed);
    let unknown = results.iter().any(|(verdict, _)| *verdict == GroupVerdict::Unknown);
    if unknown && !failed {
        family.blind = family.blind.saturating_add(1);
        if family.blind >= 3 {
            routes.clear_link_health_for_family(link_id, ipv6).await;
            family.evaluator =
                HealthEvaluator::new(link_id, cfg.failure_threshold, cfg.recovery_threshold, 1);
        }
        return;
    }
    family.blind = 0;
    // The group reduction is exact: DNS failure cannot be hidden by unrelated ping successes.
    let rtt = if failed {
        None
    } else {
        results
            .iter()
            .flat_map(|(_, r)| r.iter())
            .filter_map(|(_, r)| r.as_ref().ok().copied().flatten())
            .max()
    };
    family.evaluator.apply_round(&[TargetProbe { target: groups[0].targets[0].address(), rtt }]);
    routes.update_link_health_for_family(family.evaluator.info().clone(), ipv6).await;
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    link_id: Uuid,
    iface: SessionIface,
    state: LinkStateHandle,
    cfg: RuntimeWanLinkHealthCheckConfig,
    status: ServiceHandle,
    probe: Arc<dyn WanHealthProbe>,
    routes: IpRouteService,
    runtime: Arc<ArcSwap<HealthCheckRuntime>>,
    groups: Vec<WanProbeGroup>,
) {
    let mut v4 = FamilyState::new(link_id, &cfg);
    let mut v6 = FamilyState::new(link_id, &cfg);
    let stop = status.stop_token();
    let mut state_changes = state.subscribe();
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs.max(1).into()));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    status.just_change_status(ServiceStatus::Running);
    loop {
        tokio::select! { _ = stop.cancelled() => break, _ = ticker.tick() => {}, changed = state_changes.changed() => { if changed.is_err() { break; } } }
        let snapshot = state.snapshot();
        let source4 = snapshot.session.v4_ip();
        let source6 = match snapshot.session.wan_v6_addr() {
            Some(ip) => Some(IpAddr::V6(ip)),
            None => routes
                .get_ipv6_wan_route(
                    &landscape_common::sys_service::route_service::RouteOwner::Link(link_id),
                )
                .await
                .map(|route| route.iface_ip)
                .filter(|ip| ip.is_ipv6() && !ip.is_unspecified()),
        };
        let rounds = async {
            tokio::join!(
                round(&mut v4, source4, false, link_id, &iface, &groups, &cfg, &probe, &routes),
                round(&mut v6, source6, true, link_id, &iface, &groups, &cfg, &probe, &routes),
            );
        };
        tokio::select! { _ = stop.cancelled() => break, _ = rounds => {}, _ = state_changes.changed() => { ticker.reset_immediately(); continue; } }
        super::health_check::sync_followed_family(&routes, link_id, &cfg).await;
        swap_if_changed(
            &runtime,
            super::health_check::runtime_snapshot(
                &cfg,
                Some(v4.evaluator.info()),
                Some(v6.evaluator.info()),
                v4.probes.iter().chain(v6.probes.iter()).cloned().collect(),
            ),
        );
    }
    routes.clear_link_health(link_id).await;
    status.just_change_status(ServiceStatus::Stop);
    swap_if_changed(&runtime, HealthCheckRuntime::Stopped);
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::wan_link::WanProbeTarget;
    #[tokio::test]
    async fn disabled_families_do_not_attempt_any_targets() {
        use super::super::probe::FakeProbe;
        use landscape_common::wan_link::{RuntimeWanLinkConfig, WanLinkConfig};
        let link: WanLinkConfig =
            serde_json::from_value(serde_json::json!({"attach_iface_name":"eth0"})).unwrap();
        let mut cfg = RuntimeWanLinkConfig::from_config(&link).health_check;
        let routes = landscape_core::route::test_used_ip_route();
        let probe: Arc<dyn WanHealthProbe> =
            Arc::new(FakeProbe(|_| panic!("disabled IPv4 probed")));
        for ipv6 in [false, true] {
            cfg.ipv4_probe_enabled = ipv6;
            cfg.ipv6_probe_enabled = !ipv6;
            let mut family = FamilyState::new(link.id, &cfg);
            let address = if ipv6 { "2001:db8::1" } else { "192.0.2.1" }.parse().unwrap();
            let groups = vec![WanProbeGroup {
                name: "disabled".into(),
                quorum: 1,
                targets: vec![WanProbeTarget::Icmp { address }],
            }];
            round(
                &mut family,
                Some(address),
                ipv6,
                link.id,
                &SessionIface::new(1, "eth0", None),
                &groups,
                &cfg,
                &probe,
                &routes,
            )
            .await;
            assert!(family.source.is_none() && family.probes.is_empty());
            assert!(routes.get_link_health_for_family(link.id, ipv6).await.is_none());
        }
    }

    #[test]
    fn locally_broken_probe_does_not_reduce_quorum() {
        assert_eq!(group_verdict(1, 1, 2), GroupVerdict::Unknown);
        assert_eq!(group_verdict(1, 0, 2), GroupVerdict::Failed);
        assert_eq!(group_verdict(2, 1, 2), GroupVerdict::Healthy);
    }
}
