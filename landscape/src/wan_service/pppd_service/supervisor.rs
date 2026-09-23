use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use landscape_common::service::ServiceStatus;
use landscape_common::service::WatchService;

use super::env::{PppIpv4State, PppdChild, PppdEnv, PppdTimings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackoffOutcome {
    Stop,
    Elapsed,
}

pub(crate) struct PppdRetryController {
    failure_count: u32,
}

impl PppdRetryController {
    pub(crate) fn new() -> Self {
        Self { failure_count: 0 }
    }

    pub(crate) fn failure_count(&self) -> u32 {
        self.failure_count
    }

    pub(crate) fn note_failure(&mut self, timings: &PppdTimings) -> Duration {
        self.failure_count = self.failure_count.saturating_add(1);
        timings.backoff(self.failure_count)
    }

    pub(crate) fn note_healthy(&mut self) {
        self.failure_count = 0;
    }
}

pub(crate) struct PppSessionHealth {
    baseline: PppIpv4State,
    saw_reset: bool,
    healthy_once: bool,
}

impl PppSessionHealth {
    pub(crate) fn new(baseline: PppIpv4State) -> Self {
        let saw_reset = !baseline.is_ready();
        Self { baseline, saw_reset, healthy_once: false }
    }

    pub(crate) fn observe(&mut self, current: &PppIpv4State) -> bool {
        if !current.is_ready() {
            self.saw_reset = true;
        }

        if !self.healthy_once && current.is_ready() && (self.saw_reset || *current != self.baseline)
        {
            self.healthy_once = true;
            return true;
        }

        false
    }

    pub(crate) fn is_healthy(&self) -> bool {
        self.healthy_once
    }
}

async fn wait_backoff(service_status: &WatchService, backoff: Duration) -> BackoffOutcome {
    // Phase 2 will add an attach-iface `Up` branch here to interrupt the backoff
    // and redial immediately.
    tokio::select! {
        _ = service_status.wait_to_stopping() => BackoffOutcome::Stop,
        _ = tokio::time::sleep(backoff) => BackoffOutcome::Elapsed,
    }
}

async fn stop_pppd_process_async(
    child: &mut dyn PppdChild,
    ppp_iface_name: &str,
    timings: &PppdTimings,
) {
    match child.try_wait() {
        Ok(Some(status)) => {
            tracing::info!(
                "pppd process for {} already exited before stop handling: {:?}",
                ppp_iface_name,
                status
            );
            return;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("failed to probe pppd child state for {}: {}", ppp_iface_name, e);
        }
    }

    if let Err(e) = child.signal_group(libc::SIGTERM).await {
        tracing::warn!(
            "failed to send SIGTERM to pppd process group for {}: {}",
            ppp_iface_name,
            e
        );
    }

    match tokio::time::timeout(timings.stop_grace, child.wait()).await {
        Ok(Ok(status)) => {
            tracing::info!(
                "pppd process for {} exited after SIGTERM: {:?}",
                ppp_iface_name,
                status
            );
            return;
        }
        Ok(Err(e)) => {
            tracing::warn!(
                "failed while waiting for pppd process {} to exit: {}",
                ppp_iface_name,
                e
            );
        }
        Err(_) => {
            tracing::warn!(
                "pppd process group for {} did not exit within {:?}; escalating to SIGKILL",
                ppp_iface_name,
                timings.stop_grace
            );
        }
    }

    if let Err(e) = child.signal_group(libc::SIGKILL).await {
        tracing::warn!(
            "failed to send SIGKILL to pppd process group for {}: {}",
            ppp_iface_name,
            e
        );
    }

    match tokio::time::timeout(timings.stop_kill_wait, child.wait()).await {
        Ok(Ok(status)) => {
            tracing::info!(
                "pppd process for {} exited after SIGKILL: {:?}",
                ppp_iface_name,
                status
            );
        }
        Ok(Err(e)) => {
            tracing::error!(
                "failed while waiting for pppd process {} after SIGKILL: {}",
                ppp_iface_name,
                e
            );
        }
        Err(_) => {
            tracing::error!(
                "pppd process for {} still did not exit after SIGKILL within {:?}",
                ppp_iface_name,
                timings.stop_kill_wait
            );
        }
    }
}

/// Supervises the `pppd` child process: dials, watches the acquired IPv4 address,
/// and redials on failure. Returns `false` only when the supervisor itself
/// panicked/cancelled, `true` on a graceful stop.
///
/// The environment cleanup (route/binding teardown) always runs once on exit,
/// including when the supervisor loop panics.
pub(crate) async fn run_pppd_supervisor(
    ppp_iface_name: String,
    as_router: bool,
    service_status: WatchService,
    env: Arc<dyn PppdEnv>,
    timings: PppdTimings,
) -> bool {
    let graceful = AssertUnwindSafe(supervise_loop(
        ppp_iface_name.clone(),
        as_router,
        service_status,
        env.clone(),
        timings,
    ))
    .catch_unwind()
    .await
    .unwrap_or_else(|_| {
        tracing::error!("pppd supervisor panicked");
        false
    });

    env.cleanup(&ppp_iface_name, as_router).await;
    graceful
}

async fn supervise_loop(
    ppp_iface_name: String,
    as_router: bool,
    service_status: WatchService,
    env: Arc<dyn PppdEnv>,
    timings: PppdTimings,
) -> bool {
    let mut retry = PppdRetryController::new();
    let mut ticker = tokio::time::interval(timings.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    'restart: loop {
        match service_status.current() {
            ServiceStatus::Stopping | ServiceStatus::Stop => return true,
            ServiceStatus::Failed => return false,
            _ => {}
        }

        let baseline = env.poll_addr(&ppp_iface_name).await;
        let mut last_state = baseline.clone();
        let mut health = PppSessionHealth::new(baseline);
        let startup_deadline = tokio::time::Instant::now() + timings.startup_timeout;

        tracing::info!("Starting PPPD for {}", ppp_iface_name);
        let mut child = match env.spawn(&ppp_iface_name).await {
            Ok(child) => child,
            Err(e) => {
                let backoff = retry.note_failure(&timings);
                tracing::error!(
                    "failed to start pppd: {}, retrying after {:?} (failure_count={})",
                    e,
                    backoff,
                    retry.failure_count()
                );
                match wait_backoff(&service_status, backoff).await {
                    BackoffOutcome::Stop => return true,
                    BackoffOutcome::Elapsed => continue 'restart,
                }
            }
        };

        let mut should_stop = false;
        loop {
            tokio::select! {
                _ = service_status.wait_to_stopping() => {
                    tracing::info!("Received stop signal for PPPD");
                    should_stop = true;
                    break;
                }
                status = child.wait() => {
                    tracing::warn!("pppd exited with status: {:?}", status);
                    break;
                }
                _ = ticker.tick() => {
                    let state = env.poll_addr(&ppp_iface_name).await;
                    if state.is_ready() && state != last_state {
                        env.on_addr_ready(&state, as_router, &ppp_iface_name).await;
                    }

                    if health.observe(&state) {
                        retry.note_healthy();
                    }
                    last_state = state;

                    if !health.is_healthy() && tokio::time::Instant::now() >= startup_deadline {
                        tracing::warn!(
                            "pppd startup timed out after {:?} without acquiring IPv4 local/peer addresses on {}",
                            timings.startup_timeout,
                            ppp_iface_name
                        );
                        break;
                    }
                }
            }
        }

        stop_pppd_process_async(child.as_mut(), &ppp_iface_name, &timings).await;

        if should_stop {
            return true;
        }

        let backoff = retry.note_failure(&timings);
        tracing::warn!(
            "pppd connection lost, retrying after {:?} (failure_count={})",
            backoff,
            retry.failure_count()
        );
        match wait_backoff(&service_status, backoff).await {
            BackoffOutcome::Stop => return true,
            BackoffOutcome::Elapsed => {}
        }
    }
}
