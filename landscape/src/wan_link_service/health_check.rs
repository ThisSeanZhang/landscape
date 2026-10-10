//! Health-check section runner: probes every target in parallel through
//! the link's own iface and source address, feeds the debounced evaluator
//! and pushes snapshots to the route service. Section status mirrors the
//! checker lifecycle only; the verdict lives in the route service.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::sys_service::route_service::RouteOwner;
use landscape_common::wan_link::{
    HealthEvaluator, LinkStateHandle, RuntimeWanHealthProbe, RuntimeWanLinkHealthCheckConfig,
    SessionIface, TargetProbe, WanLinkHealthState,
};
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

use super::probe::WanHealthProbe;

pub(super) async fn run(
    link_id: Uuid,
    iface: SessionIface,
    link_state: LinkStateHandle,
    config: RuntimeWanLinkHealthCheckConfig,
    service_status: ServiceHandle,
    probe: Arc<dyn WanHealthProbe>,
    route_service: IpRouteService,
) {
    let stop = service_status.stop_token();

    // The framework restarts the section on every epoch bump, so the lease
    // address is stable for this whole run.
    let Some(IpAddr::V4(src)) = link_state.snapshot().session.v4_ip() else {
        service_status.just_change_status(ServiceStatus::Failed);
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

    let mut ticker = tokio::time::interval(Duration::from_secs(config.interval_secs.max(1).into()));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = ticker.tick() => {
                let round_targets =
                    round_targets(&route_service, link_id, &targets, probe_gateway).await;
                if round_targets.is_empty() {
                    continue;
                }
                let results = probe_round(&probe, &iface.iface_name, src, &round_targets, config.timeout_ms)
                    .await;
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
            }
        }
    }

    route_service.clear_link_health(link_id).await;
    service_status.just_change_status(ServiceStatus::Stop);
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
) -> Vec<TargetProbe> {
    let timeout = Duration::from_millis(timeout_ms.into());
    join_all(targets.iter().map(|&target| {
        let probe = probe.clone();
        let dev = dev.to_string();
        async move {
            let rtt = match probe.ping_v4(&dev, src, target, timeout).await {
                Ok(rtt) => rtt,
                Err(err) => {
                    tracing::warn!(iface = %dev, target = %target, error = %err, "health-check probe error");
                    None
                }
            };
            TargetProbe { target, rtt }
        }
    }))
    .await
}
