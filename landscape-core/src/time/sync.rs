use std::{
    io,
    sync::Arc,
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use landscape_common::{
    concurrency::thread_name,
    config::TimeRuntimeConfig,
    memtrack::{TaggedFuture, subsystem_from_task_label},
    sys_service::time_sync::{
        TimeSyncAction, TimeSyncError, TimeSyncSource, TimeSyncStage, TimeSyncStatus,
    },
    utils::time::now_ms,
};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use super::ntp::{NtpClient, NtpQueryResult, UdpNtpClient};

const BACKOFF_INITIAL_SECS: u64 = 5;
const BACKOFF_MAX_SECS: u64 = 300;
const SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// Abstract system clock stepping so tests never touch the real clock.
#[async_trait]
pub trait SystemClock: Send + Sync {
    async fn set_time(&self, time: SystemTime) -> io::Result<()>;
}

pub struct RealSystemClock;

#[async_trait]
impl SystemClock for RealSystemClock {
    async fn set_time(&self, time: SystemTime) -> io::Result<()> {
        set_system_time(time)
    }
}

type StatusRef = Arc<ArcSwap<TimeSyncStatus>>;

struct ServiceInner {
    config_tx: watch::Sender<TimeRuntimeConfig>,
    status: StatusRef,
    stop_token: CancellationToken,
    sync_now: Arc<Notify>,
    tracker: TaskTracker,
}

/// Owns the background time-sync task and status. Dropping does not stop it:
/// call [`SyncTimeService::stop`] on shutdown.
#[derive(Clone)]
pub struct SyncTimeService {
    inner: Arc<ServiceInner>,
}

impl SyncTimeService {
    /// Starts the service with the production UDP NTP client and real clock.
    pub fn start(config: TimeRuntimeConfig) -> Self {
        Self::start_with(Arc::new(UdpNtpClient), Arc::new(RealSystemClock), config)
    }

    /// Starts the service with injected NTP client and clock (tests).
    pub fn start_with(
        ntp_client: Arc<dyn NtpClient>,
        system_clock: Arc<dyn SystemClock>,
        config: TimeRuntimeConfig,
    ) -> Self {
        let config = normalized_time_config(config);
        let enabled = config.enabled;
        let (config_tx, config_rx) = watch::channel(config);
        let status: StatusRef = Arc::new(ArcSwap::from_pointee(TimeSyncStatus {
            enabled,
            running: true,
            current_source: TimeSyncSource::System,
            sync_stage: TimeSyncStage::Startup,
            last_action: TimeSyncAction::Startup,
            ..Default::default()
        }));
        let stop_token = CancellationToken::new();
        let sync_now = Arc::new(Notify::new());
        let tracker = TaskTracker::new();

        tracker.spawn(
            TaggedFuture::new(
                subsystem_from_task_label(thread_name::fixed::TIME_SYNC),
                run_time_sync_loop(
                    ntp_client,
                    system_clock,
                    config_rx,
                    stop_token.clone(),
                    Arc::clone(&sync_now),
                    Arc::clone(&status),
                ),
            )
            .instrument(tracing::info_span!("task", task = thread_name::fixed::TIME_SYNC)),
        );

        Self {
            inner: Arc::new(ServiceInner { config_tx, status, stop_token, sync_now, tracker }),
        }
    }

    pub fn update_config(&self, config: TimeRuntimeConfig) {
        let config = normalized_time_config(config);
        let _ = self.inner.config_tx.send(config.clone());
        store_status(&self.inner.status, |status| status.enabled = config.enabled);
    }

    pub fn status(&self) -> TimeSyncStatus {
        self.inner.status.load_full().as_ref().clone()
    }

    /// Requests an immediate sync; errors when the service is disabled.
    pub fn sync_now(&self) -> Result<(), TimeSyncError> {
        if !self.inner.config_tx.borrow().enabled {
            return Err(TimeSyncError::SyncDisabled);
        }
        self.inner.sync_now.notify_one();
        Ok(())
    }

    /// Cancels the sync task and waits (bounded) for it to finish.
    pub async fn stop(&self) {
        let timeout = StdDuration::from_secs(SHUTDOWN_TIMEOUT_SECS);
        self.inner.stop_token.cancel();
        self.inner.tracker.close();
        match tokio::time::timeout(timeout, self.inner.tracker.wait()).await {
            Ok(()) => tracing::info!("time sync task stopped"),
            Err(_) => tracing::warn!(
                "time sync shutdown timed out after {timeout:?}; in-flight query may still be draining"
            ),
        }
    }
}

fn normalized_time_config(mut config: TimeRuntimeConfig) -> TimeRuntimeConfig {
    config.sync_interval_secs = config.sync_interval_secs.max(1);
    config.timeout_secs = config.timeout_secs.max(1);
    config.samples_per_server = config.samples_per_server.max(1);
    config
}

fn store_status(status: &StatusRef, mutate: impl Fn(&mut TimeSyncStatus)) {
    status.rcu(|current| {
        let mut next = TimeSyncStatus::clone(current);
        mutate(&mut next);
        Arc::new(next)
    });
}

fn record_disabled_status(status: &StatusRef) {
    store_status(status, |next| {
        next.enabled = false;
        next.running = true;
        next.current_source = TimeSyncSource::System;
        next.sync_stage = TimeSyncStage::Disabled;
        next.last_action = TimeSyncAction::Disabled;
        next.last_server = None;
        next.last_offset_ms = None;
        next.last_delay_ms = None;
        next.selected_sample_count = None;
        next.last_error = None;
        next.system_clock_synced = true;
        next.next_attempt_in_secs = None;
    });
}

fn action_label(is_initial: bool, step_threshold_ms: u64, offset_ms: f64) -> TimeSyncAction {
    if is_initial {
        TimeSyncAction::InitialStep
    } else if offset_ms.abs() > step_threshold_ms as f64 {
        TimeSyncAction::PeriodicStep
    } else {
        TimeSyncAction::PeriodicRefresh
    }
}

fn record_ntp_success(
    status: &StatusRef,
    result: &NtpQueryResult,
    attempt_at: f64,
    is_initial: bool,
    action: TimeSyncAction,
) {
    store_status(status, |next| {
        next.enabled = true;
        next.running = true;
        next.current_source = TimeSyncSource::Ntp;
        next.sync_stage = if is_initial { TimeSyncStage::Initial } else { TimeSyncStage::Steady };
        next.last_action = action;
        next.last_attempt_at = Some(attempt_at);
        next.last_success_at = Some(attempt_at);
        next.last_system_clock_update_at = Some(attempt_at);
        next.last_server = Some(result.server.clone());
        next.last_offset_ms = Some(result.offset_ms);
        next.last_delay_ms = Some(result.delay_ms);
        next.selected_sample_count = Some(result.sample_count);
        next.last_error = None;
        next.system_clock_synced = true;
    });
}

fn record_ntp_error(
    status: &StatusRef,
    error: &str,
    attempt_at: f64,
    system_clock_synced: bool,
    backoff_secs: u64,
) {
    store_status(status, |next| {
        next.enabled = true;
        next.running = true;
        next.current_source = TimeSyncSource::System;
        next.sync_stage = TimeSyncStage::Fallback;
        next.last_action = TimeSyncAction::FallbackSystem;
        next.last_attempt_at = Some(attempt_at);
        next.last_error = Some(error.to_string());
        next.system_clock_synced = system_clock_synced;
        next.next_attempt_in_secs = Some(backoff_secs);
    });
}

fn record_ntp_set_failure(
    status: &StatusRef,
    result: &NtpQueryResult,
    attempt_at: f64,
    error: &str,
    backoff_secs: u64,
) {
    store_status(status, |next| {
        next.enabled = true;
        next.running = true;
        next.current_source = TimeSyncSource::System;
        next.sync_stage = TimeSyncStage::Error;
        next.last_action = TimeSyncAction::NtpSetFailed;
        next.last_attempt_at = Some(attempt_at);
        // The query succeeded but the clock was not stepped, so this is not a
        // success: keep `last_success_at` unset so `is_initial` stays accurate.
        next.last_server = Some(result.server.clone());
        next.last_offset_ms = Some(result.offset_ms);
        next.last_delay_ms = Some(result.delay_ms);
        next.selected_sample_count = Some(result.sample_count);
        next.last_error = Some(error.to_string());
        next.system_clock_synced = false;
        next.next_attempt_in_secs = Some(backoff_secs);
    });
}

/// Sync loop. Config changes and manual triggers wake it; disabled configs park it.
async fn run_time_sync_loop(
    ntp_client: Arc<dyn NtpClient>,
    system_clock: Arc<dyn SystemClock>,
    mut config_rx: watch::Receiver<TimeRuntimeConfig>,
    stop_token: CancellationToken,
    sync_now: Arc<Notify>,
    status: StatusRef,
) {
    let mut backoff_secs: u64 = 0;
    let mut first_run = true;

    loop {
        let config = config_rx.borrow_and_update().clone();

        if !config.enabled {
            record_disabled_status(&status);
            tokio::select! {
                biased;
                _ = stop_token.cancelled() => return,
                changed = config_rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    backoff_secs = 0;
                    first_run = true;
                }
            }
            continue;
        }

        let period_secs = if first_run {
            0
        } else if backoff_secs > 0 {
            backoff_secs
        } else {
            config.sync_interval_secs
        };

        store_status(&status, |next| {
            next.enabled = true;
            next.running = true;
            next.next_attempt_in_secs = Some(period_secs);
        });

        tokio::select! {
            biased;
            _ = stop_token.cancelled() => return,
            changed = config_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                backoff_secs = 0;
                first_run = true;
                continue;
            }
            _ = sync_now.notified() => {
                backoff_secs = 0;
                first_run = false;
            }
            _ = tokio::time::sleep(StdDuration::from_secs(period_secs)) => {
                first_run = false;
            }
        }

        let attempt_at = now_ms() as f64;
        let is_initial = status.load().last_success_at.is_none();

        let query_result = tokio::select! {
            biased;
            _ = stop_token.cancelled() => return,
            result = ntp_client.query(
                &config.servers,
                StdDuration::from_secs(config.timeout_secs),
                config.samples_per_server,
            ) => result,
        };

        match query_result {
            Ok(result) => match system_clock.set_time(result.synced_time).await {
                Ok(()) => {
                    backoff_secs = 0;
                    let action =
                        action_label(is_initial, config.step_threshold_ms, result.offset_ms);
                    tracing::info!(
                        server = %result.server,
                        action = %action,
                        offset_ms = result.offset_ms,
                        delay_ms = result.delay_ms,
                        "System time updated from NTP sync"
                    );
                    record_ntp_success(&status, &result, attempt_at, is_initial, action);
                }
                Err(err) => {
                    backoff_secs = advance_backoff(backoff_secs);
                    tracing::warn!(
                        server = %result.server,
                        error = %err,
                        "NTP sync succeeded but failed to update system clock"
                    );
                    record_ntp_set_failure(
                        &status,
                        &result,
                        attempt_at,
                        &err.to_string(),
                        backoff_secs,
                    );
                }
            },
            Err(err) => {
                backoff_secs = advance_backoff(backoff_secs);
                tracing::warn!(
                    error = %err,
                    "NTP sync failed, falling back to system clock"
                );
                // Only claim the clock is synced if we stepped it at least once.
                let system_clock_synced = status.load().last_system_clock_update_at.is_some();
                record_ntp_error(
                    &status,
                    &err.to_string(),
                    attempt_at,
                    system_clock_synced,
                    backoff_secs,
                );
            }
        }
    }
}

fn advance_backoff(current: u64) -> u64 {
    if current == 0 { BACKOFF_INITIAL_SECS } else { (current * 2).min(BACKOFF_MAX_SECS) }
}

pub fn set_system_time(time: SystemTime) -> io::Result<()> {
    let duration = time.duration_since(UNIX_EPOCH).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "system time is before UNIX_EPOCH")
    })?;

    let ts = libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    };

    let result = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

#[cfg(test)]
mod tests;
