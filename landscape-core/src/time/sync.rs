use std::{
    io,
    sync::{Arc, Mutex, RwLock},
    time::{Duration as StdDuration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use landscape_common::{
    concurrency::{spawn_task, thread_name},
    config::TimeRuntimeConfig,
    sys_service::time_sync::{TimeSyncAction, TimeSyncSource, TimeSyncStage, TimeSyncStatus},
    utils::time::now_ms,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::ntp::{NtpClient, NtpQueryResult, UdpNtpClient};

const BACKOFF_INITIAL_SECS: u64 = 5;
const BACKOFF_MAX_SECS: u64 = 300;
const STOP_TIMEOUT_SECS: u64 = 5;

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

type StatusRef = Arc<RwLock<TimeSyncStatus>>;

struct ServiceInner {
    config_tx: watch::Sender<TimeRuntimeConfig>,
    status: StatusRef,
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// Owns the background time-sync task: steps the system clock per config and
/// keeps [`TimeSyncStatus`]. Config changes wake the task immediately through a
/// `watch` channel; when disabled it parks without polling. Dropping is not a
/// shutdown: call [`SyncTimeService::stop`] (used by the app shutdown path).
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
        let status: StatusRef = Arc::new(RwLock::new(TimeSyncStatus {
            enabled,
            running: true,
            current_source: TimeSyncSource::System,
            sync_stage: TimeSyncStage::Startup,
            last_action: TimeSyncAction::Startup,
            ..Default::default()
        }));
        let cancel = CancellationToken::new();

        let task = spawn_task(
            thread_name::fixed::TIME_SYNC,
            run_time_sync_loop(
                ntp_client,
                system_clock,
                config_rx,
                cancel.clone(),
                Arc::clone(&status),
            ),
        );

        Self {
            inner: Arc::new(ServiceInner {
                config_tx,
                status,
                cancel,
                task: Mutex::new(Some(task)),
            }),
        }
    }

    pub fn update_config(&self, config: TimeRuntimeConfig) {
        let config = normalized_time_config(config);
        let _ = self.inner.config_tx.send(config.clone());
        if let Ok(mut status) = self.inner.status.write() {
            status.enabled = config.enabled;
        }
    }

    pub fn status(&self) -> TimeSyncStatus {
        self.inner.status.read().map(|status| status.clone()).unwrap_or_default()
    }

    /// Cancels the sync task and waits (bounded) for it to finish.
    pub async fn stop(&self) {
        self.inner.cancel.cancel();
        let task = self.inner.task.lock().ok().and_then(|mut slot| slot.take());
        if let Some(task) = task
            && tokio::time::timeout(StdDuration::from_secs(STOP_TIMEOUT_SECS), task).await.is_err()
        {
            tracing::warn!("time sync task did not stop within {STOP_TIMEOUT_SECS}s");
        }
    }
}

fn normalized_time_config(mut config: TimeRuntimeConfig) -> TimeRuntimeConfig {
    config.sync_interval_secs = config.sync_interval_secs.max(1);
    config.timeout_secs = config.timeout_secs.max(1);
    config.samples_per_server = config.samples_per_server.max(1);
    config
}

fn record_disabled_status(status: &StatusRef) {
    if let Ok(mut status) = status.write() {
        status.enabled = false;
        status.running = true;
        status.current_source = TimeSyncSource::System;
        status.sync_stage = TimeSyncStage::Disabled;
        status.last_action = TimeSyncAction::Disabled;
        status.last_server = None;
        status.last_offset_ms = None;
        status.last_delay_ms = None;
        status.selected_sample_count = None;
        status.last_error = None;
        status.system_clock_synced = true;
        status.next_attempt_in_secs = None;
    }
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
    if let Ok(mut status) = status.write() {
        status.enabled = true;
        status.running = true;
        status.current_source = TimeSyncSource::Ntp;
        status.sync_stage = if is_initial { TimeSyncStage::Initial } else { TimeSyncStage::Steady };
        status.last_action = action;
        status.last_attempt_at = Some(attempt_at);
        status.last_success_at = Some(attempt_at);
        status.last_system_clock_update_at = Some(attempt_at);
        status.last_server = Some(result.server.clone());
        status.last_offset_ms = Some(result.offset_ms);
        status.last_delay_ms = Some(result.delay_ms);
        status.selected_sample_count = Some(result.sample_count);
        status.last_error = None;
        status.system_clock_synced = true;
    }
}

fn record_ntp_error(
    status: &StatusRef,
    error: &str,
    attempt_at: f64,
    system_clock_synced: bool,
    backoff_secs: u64,
) {
    if let Ok(mut status) = status.write() {
        status.enabled = true;
        status.running = true;
        status.current_source = TimeSyncSource::System;
        status.sync_stage = TimeSyncStage::Fallback;
        status.last_action = TimeSyncAction::FallbackSystem;
        status.last_attempt_at = Some(attempt_at);
        status.last_error = Some(error.to_string());
        status.system_clock_synced = system_clock_synced;
        status.next_attempt_in_secs = Some(backoff_secs);
    }
}

fn record_ntp_set_failure(
    status: &StatusRef,
    result: &NtpQueryResult,
    attempt_at: f64,
    error: &str,
    backoff_secs: u64,
) {
    if let Ok(mut status) = status.write() {
        status.enabled = true;
        status.running = true;
        status.current_source = TimeSyncSource::System;
        status.sync_stage = TimeSyncStage::Error;
        status.last_action = TimeSyncAction::NtpSetFailed;
        status.last_attempt_at = Some(attempt_at);
        // The query succeeded but the clock was not stepped, so this is not a
        // success: keep `last_success_at` unset so `is_initial` stays accurate.
        status.last_server = Some(result.server.clone());
        status.last_offset_ms = Some(result.offset_ms);
        status.last_delay_ms = Some(result.delay_ms);
        status.selected_sample_count = Some(result.sample_count);
        status.last_error = Some(error.to_string());
        status.system_clock_synced = false;
        status.next_attempt_in_secs = Some(backoff_secs);
    }
}

/// Background time-sync task: only steps the system clock per config and keeps status.
/// Config changes wake it immediately through the `watch` channel; when disabled it parks
/// without polling.
async fn run_time_sync_loop(
    ntp_client: Arc<dyn NtpClient>,
    system_clock: Arc<dyn SystemClock>,
    mut config_rx: watch::Receiver<TimeRuntimeConfig>,
    cancel: CancellationToken,
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
                _ = cancel.cancelled() => return,
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

        if let Ok(mut current) = status.write() {
            current.enabled = true;
            current.running = true;
            current.next_attempt_in_secs = Some(period_secs);
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            changed = config_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                backoff_secs = 0;
                first_run = true;
            }
            _ = tokio::time::sleep(StdDuration::from_secs(period_secs)) => {
                first_run = false;
                let attempt_at = now_ms() as f64;
                let is_initial = status
                    .read()
                    .map(|current| current.last_success_at.is_none())
                    .unwrap_or(true);

                // Cancel-aware so `stop()` does not wait out an in-flight query.
                let query_result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
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
                            let action = action_label(
                                is_initial,
                                config.step_threshold_ms,
                                result.offset_ms,
                            );
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
                        let system_clock_synced = status
                            .read()
                            .map(|current| current.last_system_clock_update_at.is_some())
                            .unwrap_or(false);
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
