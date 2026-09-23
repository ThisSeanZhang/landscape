use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use landscape_common::service::ServiceStatus;
use landscape_common::service::WatchService;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::env::{PppIpv4State, PppdChild, PppdEnv, PppdTimings};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackoffOutcome {
    Stop,
    Elapsed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionExit {
    Stop,
    Retry,
    Failed,
}

/// Resolves the session exit after the address observer failed (panicked).
///
/// A graceful stop takes precedence: an observer panic while cancelling the
/// observer during shutdown must not turn a user-initiated stop into a failure.
pub(crate) fn observer_failure_exit(exit: SessionExit) -> SessionExit {
    if exit == SessionExit::Stop {
        exit
    } else {
        SessionExit::Failed
    }
}

struct SessionResult {
    exit: SessionExit,
    child: Option<Box<dyn PppdChild>>,
    healthy: bool,
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

/// Polls and applies PPP IPv4 state independently from the process supervisor.
/// Cancellation drops an in-flight netlink poll or route update so shutdown can
/// join this task before the final route cleanup.
#[allow(clippy::too_many_arguments)] // observer 的输入（env/cancel/两个 channel）天然需要拆分传入
async fn observe_addresses(
    ppp_iface_name: String,
    as_router: bool,
    env: Arc<dyn PppdEnv>,
    timings: PppdTimings,
    cancel: CancellationToken,
    mut last_applied: Option<PppIpv4State>,
    initial_state_tx: oneshot::Sender<PppIpv4State>,
    state_tx: mpsc::UnboundedSender<PppIpv4State>,
) -> Option<PppIpv4State> {
    let initial_state = tokio::select! {
        _ = cancel.cancelled() => return last_applied,
        state = env.poll_addr(&ppp_iface_name) => state,
    };

    if initial_state_tx.send(initial_state.clone()).is_err() {
        return last_applied;
    }

    if initial_state.is_ready() && last_applied.as_ref() != Some(&initial_state) {
        tokio::select! {
            _ = cancel.cancelled() => return last_applied,
            _ = env.on_addr_ready(&initial_state, as_router, &ppp_iface_name) => {
                last_applied = Some(initial_state.clone());
            }
        }
    } else if !initial_state.is_ready() {
        last_applied = None;
    }

    let mut last_observed = initial_state;
    let first_tick = tokio::time::Instant::now() + timings.poll_interval;
    let mut ticker = tokio::time::interval_at(first_tick, timings.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return last_applied,
            _ = ticker.tick() => {
                let state = tokio::select! {
                    _ = cancel.cancelled() => return last_applied,
                    state = env.poll_addr(&ppp_iface_name) => state,
                };

                if state != last_observed {
                    if state_tx.send(state.clone()).is_err() {
                        return last_applied;
                    }

                    if state.is_ready() && last_applied.as_ref() != Some(&state) {
                        tokio::select! {
                            _ = cancel.cancelled() => return last_applied,
                            _ = env.on_addr_ready(&state, as_router, &ppp_iface_name) => {
                                last_applied = Some(state.clone());
                            }
                        }
                    } else if !state.is_ready() {
                        last_applied = None;
                    }

                    last_observed = state;
                }
            }
        }
    }
}

/// Supervises `pppd` attempts. Each attempt owns a cancellable address observer;
/// the observer is joined before stopping the process or entering backoff.
/// Environment cleanup always runs once after the observer and child are done.
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

    // TODO: bound this cleanup with a timeout when `Command` is wholesale
    // migrated to the tokio version (LD_ALL_ROUTERS still shells out via
    // blocking `std::process::Command`).
    env.cleanup(&ppp_iface_name, as_router).await;
    graceful
}

async fn run_session(
    ppp_iface_name: &str,
    as_router: bool,
    service_status: &WatchService,
    env: Arc<dyn PppdEnv>,
    timings: &PppdTimings,
    last_applied: &mut Option<PppIpv4State>,
) -> SessionResult {
    let cancel = CancellationToken::new();
    let (initial_state_tx, initial_state_rx) = oneshot::channel();
    let (state_tx, mut state_rx) = mpsc::unbounded_channel();
    let observer_cancel = cancel.clone();
    let observer_env = env.clone();
    let observer_iface = ppp_iface_name.to_string();
    let observer_timings = timings.clone();
    let observer_last_applied = last_applied.clone();
    let observer: JoinHandle<Option<PppIpv4State>> = tokio::spawn(observe_addresses(
        observer_iface,
        as_router,
        observer_env,
        observer_timings,
        observer_cancel,
        observer_last_applied,
        initial_state_tx,
        state_tx,
    ));

    let session = AssertUnwindSafe(async {
        if matches!(service_status.current(), ServiceStatus::Stopping | ServiceStatus::Stop) {
            return SessionResult { exit: SessionExit::Stop, child: None, healthy: false };
        }

        let baseline = tokio::select! {
            _ = service_status.wait_to_stopping() => {
                return SessionResult { exit: SessionExit::Stop, child: None, healthy: false };
            }
            initial_state = initial_state_rx => match initial_state {
                Ok(state) => state,
                Err(_) => {
                    return SessionResult { exit: SessionExit::Failed, child: None, healthy: false };
                }
            }
        };
        let mut health = PppSessionHealth::new(baseline);

        let mut child = match env.spawn(ppp_iface_name).await {
            Ok(child) => child,
            Err(e) => {
                tracing::error!("failed to start pppd: {e}");
                return SessionResult { exit: SessionExit::Retry, child: None, healthy: false };
            }
        };
        let startup_deadline = tokio::time::Instant::now() + timings.startup_timeout;
        let startup_timeout = tokio::time::sleep_until(startup_deadline);
        tokio::pin!(startup_timeout);

        let mut exit = SessionExit::Retry;
        let mut healthy_once = false;
        loop {
            tokio::select! {
                _ = service_status.wait_to_stopping() => {
                    tracing::info!("Received stop signal for PPPD");
                    exit = SessionExit::Stop;
                    break;
                }
                status = child.wait() => {
                    tracing::warn!("pppd exited with status: {:?}", status);
                    break;
                }
                state = state_rx.recv() => match state {
                    Some(state) => {
                        if health.observe(&state) {
                            healthy_once = true;
                        }
                    }
                    None => {
                        tracing::error!("pppd address observer stopped unexpectedly");
                        exit = SessionExit::Failed;
                        break;
                    }
                },
                _ = &mut startup_timeout, if !health.is_healthy() => {
                    tracing::warn!(
                        "pppd startup timed out after {:?} without acquiring IPv4 local/peer addresses on {}",
                        timings.startup_timeout,
                        ppp_iface_name
                    );
                    break;
                }
            }
        }

        SessionResult { exit, child: Some(child), healthy: healthy_once }
    })
    .catch_unwind()
    .await
    .unwrap_or_else(|_| {
        tracing::error!("pppd session supervisor panicked");
        SessionResult { exit: SessionExit::Failed, child: None, healthy: false }
    });

    cancel.cancel();
    let observer_result = observer.await;
    let observer_failed = match observer_result {
        Ok(applied) => {
            *last_applied = applied;
            false
        }
        Err(_) => true,
    };

    let mut session = session;
    if observer_failed {
        if session.exit == SessionExit::Stop {
            tracing::warn!("address observer panicked during graceful stop; keeping Stop");
        } else {
            tracing::error!("pppd address observer panicked");
            session.exit = observer_failure_exit(session.exit);
        }
    }

    if let Some(mut child) = session.child.take() {
        stop_pppd_process_async(child.as_mut(), ppp_iface_name, timings).await;
    }

    session
}

async fn supervise_loop(
    ppp_iface_name: String,
    as_router: bool,
    service_status: WatchService,
    env: Arc<dyn PppdEnv>,
    timings: PppdTimings,
) -> bool {
    let mut retry = PppdRetryController::new();
    let mut last_applied = None;

    loop {
        match service_status.current() {
            ServiceStatus::Stopping | ServiceStatus::Stop => return true,
            ServiceStatus::Failed => return false,
            _ => {}
        }

        tracing::info!("Starting PPPD for {}", ppp_iface_name);
        let session = run_session(
            &ppp_iface_name,
            as_router,
            &service_status,
            env.clone(),
            &timings,
            &mut last_applied,
        )
        .await;

        if session.healthy {
            retry.note_healthy();
        }

        match session.exit {
            SessionExit::Stop => return true,
            SessionExit::Failed => return false,
            SessionExit::Retry => {
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
    }
}
