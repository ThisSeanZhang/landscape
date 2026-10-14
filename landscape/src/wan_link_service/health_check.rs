//! Health-check section runner: probes every target in parallel through
//! the link's own iface and source address, feeds the debounced evaluator
//! and pushes snapshots to the route service. Section status mirrors the
//! checker lifecycle only; the verdict lives in the route service.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use futures::future::join_all;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::sys_service::route_service::RouteOwner;
use landscape_common::wan_link::{HealthCheckRuntime, HealthProbeStatus};
use landscape_common::wan_link::{
    HealthEvaluator, LinkStateHandle, RuntimeWanHealthProbe, RuntimeWanLinkHealthCheckConfig,
    SessionIface, TargetProbe, WanLinkHealthInfo, WanLinkHealthState, swap_if_changed,
};
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

use super::probe::WanHealthProbe;

/// Consecutive all-error ("blind") rounds tolerated before the section
/// fails itself instead of judging the link.
const HEALTH_BLIND_ROUNDS: u32 = 3;

/// What one probe round produced for the runner.
#[derive(Debug)]
enum RoundOutcome {
    /// Link evidence from the targets that could be probed; locally
    /// errored targets are excluded. Always non-empty, guaranteed by the
    /// caller's empty-targets guard.
    Evidence(Vec<TargetProbe>),
    /// Every target failed locally; no link verdict can be drawn.
    Blind { errored: usize },
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    link_id: Uuid,
    iface: SessionIface,
    link_state: LinkStateHandle,
    config: RuntimeWanLinkHealthCheckConfig,
    service_status: ServiceHandle,
    probe: Arc<dyn WanHealthProbe>,
    route_service: IpRouteService,
    runtime: Arc<ArcSwap<HealthCheckRuntime>>,
) {
    let stop = service_status.stop_token();

    // This section runs with SectionScope::SessionAndLease: the framework
    // restarts it when the lease address changes, so the probe source ip is
    // stable for this whole run.
    let Some(IpAddr::V4(src)) = link_state.snapshot().session.v4_ip() else {
        service_status.just_change_status(ServiceStatus::Failed);
        swap_if_changed(&runtime, HealthCheckRuntime::Stopped);
        return;
    };

    let RuntimeWanHealthProbe::Icmp { targets, probe_gateway } = config.probe;
    let mut evaluator = HealthEvaluator::new(
        link_id,
        config.failure_threshold,
        config.recovery_threshold,
        config.reliability,
    );

    // Silent init push (Unknown -> Unknown never broadcasts).
    route_service.update_link_health(evaluator.info().clone()).await;

    service_status.just_change_status(ServiceStatus::Running);
    swap_if_changed(
        &runtime,
        HealthCheckRuntime::Running {
            state: evaluator.info().state,
            rtt_ewma_ms: evaluator.info().rtt_ewma_ms,
            probes: targets
                .iter()
                .map(|target| HealthProbeStatus { target: *target, rtt_ms: None })
                .collect(),
        },
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(config.interval_secs.max(1).into()));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut blind_rounds: u32 = 0;
    let mut failed = false;

    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = ticker.tick() => {
                let round_targets =
                    round_targets(&route_service, link_id, &targets, probe_gateway).await;
                if round_targets.is_empty() {
                    continue;
                }
                match probe_round(&probe, &iface.iface_name, src, &round_targets, config.timeout_ms)
                    .await
                {
                    RoundOutcome::Evidence(results) => {
                        blind_rounds = 0;
                        if let Some(transition) = evaluator.apply_round(&results) {
                            match transition.to {
                                WanLinkHealthState::Healthy => tracing::info!(
                                    iface = %iface.iface_name,
                                    link = %link_id,
                                    rtt_ewma_ms = evaluator.info().rtt_ewma_ms,
                                    "health-check: link is healthy"
                                ),
                                WanLinkHealthState::Unhealthy => tracing::warn!(
                                    iface = %iface.iface_name,
                                    link = %link_id,
                                    consecutive_failures = evaluator.info().consecutive_failures,
                                    "health-check: link judged unhealthy"
                                ),
                                WanLinkHealthState::Unknown => {}
                            }
                        }
                        route_service.update_link_health(evaluator.info().clone()).await;
                        publish_round(
                            &runtime,
                            evaluator.info(),
                            &round_targets,
                            Some(&results),
                        );
                    }
                    RoundOutcome::Blind { errored } => {
                        blind_rounds += 1;
                        if blind_rounds >= HEALTH_BLIND_ROUNDS {
                            tracing::error!(
                                iface = %iface.iface_name,
                                link = %link_id,
                                blind_rounds,
                                errored,
                                "health-check: probing is broken locally, failing the section"
                            );
                            failed = true;
                            break;
                        }
                        publish_round(&runtime, evaluator.info(), &round_targets, None);
                    }
                }
            }
        }
    }

    route_service.clear_link_health(link_id).await;
    service_status.just_change_status(if failed {
        ServiceStatus::Failed
    } else {
        ServiceStatus::Stop
    });
    swap_if_changed(&runtime, HealthCheckRuntime::Stopped);
}

fn publish_round(
    runtime: &Arc<ArcSwap<HealthCheckRuntime>>,
    info: &WanLinkHealthInfo,
    attempted: &[Ipv4Addr],
    evidence: Option<&Vec<TargetProbe>>,
) {
    let probes = attempted
        .iter()
        .map(|target| HealthProbeStatus {
            target: *target,
            rtt_ms: evidence.and_then(|ev| {
                ev.iter()
                    .find(|p| p.target == *target)
                    .and_then(|p| p.rtt.map(|rtt| rtt.as_millis() as u64))
            }),
        })
        .collect();
    swap_if_changed(
        runtime,
        HealthCheckRuntime::Running {
            state: info.state,
            rtt_ewma_ms: info.rtt_ewma_ms,
            probes,
        },
    );
}

/// The round's target list: configured targets plus the link's current
/// gateway (re-resolved every round; it may change without an epoch bump).
async fn round_targets(
    route_service: &IpRouteService,
    link_id: Uuid,
    targets: &[Ipv4Addr],
    probe_gateway: bool,
) -> Vec<Ipv4Addr> {
    let mut round = targets.to_vec();
    if probe_gateway
        && let Some(info) = route_service.get_ipv4_wan_route(&RouteOwner::Link(link_id)).await
        && let IpAddr::V4(gateway) = info.gateway_ip
        && !gateway.is_unspecified()
        && !round.contains(&gateway)
    {
        round.push(gateway);
    }
    round
}

/// Fan out one probe per target concurrently; a round lasts as long as its
/// slowest probe, independent of the target count.
async fn probe_round(
    probe: &Arc<dyn WanHealthProbe>,
    dev: &str,
    src: Ipv4Addr,
    targets: &[Ipv4Addr],
    timeout_ms: u16,
) -> RoundOutcome {
    let timeout = Duration::from_millis(timeout_ms.into());
    let rounds = join_all(targets.iter().map(|&target| {
        let probe = probe.clone();
        let dev = dev.to_string();
        async move {
            match probe.ping_v4(&dev, src, target, timeout).await {
                Ok(rtt) => Some(TargetProbe { target, rtt }),
                Err(err) => {
                    tracing::warn!(iface = %dev, target = %target, error = %err, "health-check probe error");
                    None
                }
            }
        }
    }))
    .await;

    let mut errored = 0;
    let mut evidence = Vec::with_capacity(rounds.len());
    for probe in rounds {
        match probe {
            Some(target_probe) => evidence.push(target_probe),
            None => errored += 1,
        }
    }
    if evidence.is_empty() {
        RoundOutcome::Blind { errored }
    } else {
        RoundOutcome::Evidence(evidence)
    }
}
