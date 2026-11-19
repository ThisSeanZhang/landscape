use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use arc_swap::ArcSwap;
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::sys_service::gateway::{HttpUpstreamTarget, LoadBalanceMethod};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::routes::{CompiledUpstream, HealthEndpoint, SharedGatewayRoutes};

#[derive(Clone, Default)]
pub(crate) struct GatewayHealth(Arc<ArcSwap<HashMap<HealthEndpoint, Arc<AtomicBool>>>>);

impl GatewayHealth {
    pub fn select<'a>(
        &self,
        upstream: &'a CompiledUpstream,
        seed: u64,
    ) -> Option<&'a HttpUpstreamTarget> {
        fn pick<'a>(
            count: usize,
            target: impl Fn(usize) -> &'a HttpUpstreamTarget,
            seed: u64,
            method: &LoadBalanceMethod,
        ) -> Option<&'a HttpUpstreamTarget> {
            if count == 0 {
                return None;
            }
            if count == 1 {
                return Some(target(0));
            }
            if !matches!(method, LoadBalanceMethod::Consistent) {
                return Some(target(seed as usize % count));
            }
            let total: u64 = (0..count).map(|i| u64::from(target(i).weight)).sum();
            if total == 0 {
                return Some(target(0));
            }
            // Keep the historical hash assignment when the weight sum fits in u32.
            let hash = if u32::try_from(total).is_ok() { u64::from(seed as u32) } else { seed };
            let mut point = hash % total;
            for index in 0..count {
                let entry = target(index);
                if point < u64::from(entry.weight) {
                    return Some(entry);
                }
                point -= u64::from(entry.weight);
            }
            None
        }
        if upstream.health_endpoints.is_empty() {
            return pick(
                upstream.targets.len(),
                |i| &upstream.targets[i],
                seed,
                &upstream.load_balance,
            );
        }
        let states = self.0.load();
        let eligible: Vec<_> = upstream
            .targets
            .iter()
            .zip(&upstream.health_endpoints)
            .filter(|(_, key)| states.get(key).is_none_or(|state| state.load(Ordering::Acquire)))
            .map(|(target, _)| target)
            .collect();
        pick(eligible.len(), |i| eligible[i], seed, &upstream.load_balance)
    }

    pub async fn monitor(&self, routes: &SharedGatewayRoutes, cancel: &CancellationToken) {
        let mut changed = routes.subscribe();
        let mut workers: HashMap<HealthEndpoint, ProbeWorker> = HashMap::new();
        while !cancel.is_cancelled() {
            let desired: HashSet<_> = routes.load().health_endpoints();
            let mut active = HashMap::new();
            for endpoint in desired {
                let worker = workers
                    .remove(&endpoint)
                    .unwrap_or_else(|| ProbeWorker::start(endpoint.clone(), cancel));
                active.insert(endpoint, worker);
            }
            self.0.store(Arc::new(
                active
                    .iter()
                    .map(|(key, worker)| (key.clone(), worker.available.clone()))
                    .collect(),
            ));
            stop_workers(workers).await;
            workers = active;
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = changed.changed() => if result.is_err() {break;},
            }
        }
        stop_workers(workers).await;
    }
}

struct ProbeWorker {
    available: Arc<AtomicBool>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl ProbeWorker {
    fn start(endpoint: HealthEndpoint, parent: &CancellationToken) -> Self {
        let cancel = parent.child_token();
        let available = Arc::new(AtomicBool::new(true));
        let task = spawn_task(
            task_label::task::GATEWAY_HEALTH_PROBE,
            probe(endpoint, available.clone(), cancel.clone()),
        );
        Self { available, cancel, task }
    }
}

async fn stop_workers(workers: HashMap<HealthEndpoint, ProbeWorker>) {
    for worker in workers.values() {
        worker.cancel.cancel();
    }
    for worker in workers.into_values() {
        let _ = worker.task.await;
    }
}

async fn probe(endpoint: HealthEndpoint, available: Arc<AtomicBool>, stop: CancellationToken) {
    let policy = &endpoint.policy;
    let mut tick = tokio::time::interval(Duration::from_secs(policy.interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut successes = 0u32;
    let mut failures = 0u32;
    loop {
        tokio::select! { biased; _ = stop.cancelled() => return, _ = tick.tick() => {} }
        let result = tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            result = crate::upstream::connect_tcp(&endpoint.address, endpoint.port, Duration::from_secs(policy.timeout_secs)) => result,
        };
        if result.is_ok() {
            failures = 0;
            successes = successes.saturating_add(1);
            if successes >= policy.healthy_threshold {
                available.store(true, Ordering::Release);
            }
        } else {
            successes = 0;
            failures = failures.saturating_add(1);
            if failures >= policy.unhealthy_threshold {
                available.store(false, Ordering::Release);
            }
        }
    }
}
