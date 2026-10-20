use super::*;

use std::collections::VecDeque;
use std::sync::Mutex;

#[test]
fn backoff_grows_and_caps() {
    assert_eq!(advance_backoff(0), BACKOFF_INITIAL_SECS);
    assert_eq!(advance_backoff(BACKOFF_INITIAL_SECS), BACKOFF_INITIAL_SECS * 2);
    assert_eq!(advance_backoff(BACKOFF_MAX_SECS), BACKOFF_MAX_SECS);
}

struct FakeNtpClient {
    scripted: Mutex<VecDeque<io::Result<NtpQueryResult>>>,
    queries: Mutex<Vec<usize>>,
}

impl FakeNtpClient {
    fn new(scripted: Vec<io::Result<NtpQueryResult>>) -> Arc<Self> {
        Arc::new(Self {
            scripted: Mutex::new(scripted.into_iter().collect()),
            queries: Mutex::new(Vec::new()),
        })
    }

    fn query_count(&self) -> usize {
        self.queries.lock().map(|queries| queries.len()).unwrap_or(0)
    }
}

#[async_trait]
impl NtpClient for FakeNtpClient {
    async fn query(
        &self,
        servers: &[String],
        timeout: StdDuration,
        samples_per_server: u8,
    ) -> io::Result<NtpQueryResult> {
        self.queries.lock().map(|mut queries| queries.push(servers.len())).ok();
        assert!(timeout.as_secs() >= 1);
        assert!(samples_per_server >= 1);
        self.scripted
            .lock()
            .ok()
            .and_then(|mut scripted| scripted.pop_front())
            .unwrap_or_else(|| Err(io::Error::other("no scripted result")))
    }
}

struct FakeClock {
    fail: std::sync::atomic::AtomicBool,
    set_calls: Mutex<Vec<SystemTime>>,
}

impl FakeClock {
    fn new(fail: bool) -> Arc<Self> {
        Arc::new(Self {
            fail: std::sync::atomic::AtomicBool::new(fail),
            set_calls: Mutex::new(Vec::new()),
        })
    }

    fn set_fail(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    fn set_calls(&self) -> usize {
        self.set_calls.lock().map(|calls| calls.len()).unwrap_or(0)
    }
}

#[async_trait]
impl SystemClock for FakeClock {
    async fn set_time(&self, time: SystemTime) -> io::Result<()> {
        self.set_calls.lock().map(|mut calls| calls.push(time)).ok();
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(io::Error::other("operation not permitted"))
        } else {
            Ok(())
        }
    }
}

fn ntp_ok(offset_ms: f64) -> io::Result<NtpQueryResult> {
    Ok(NtpQueryResult {
        synced_time: UNIX_EPOCH + StdDuration::from_secs(1_700_000_000),
        server: "fake.pool.ntp.org:123".to_string(),
        offset_ms,
        delay_ms: 30.0,
        sample_count: 1,
    })
}

fn ntp_err() -> io::Result<NtpQueryResult> {
    Err(io::Error::other("network unreachable"))
}

fn test_config() -> TimeRuntimeConfig {
    TimeRuntimeConfig {
        enabled: true,
        servers: vec!["fake.pool.ntp.org".to_string()],
        sync_interval_secs: 60,
        timeout_secs: 2,
        step_threshold_ms: 100,
        samples_per_server: 1,
    }
}

fn disabled_config() -> TimeRuntimeConfig {
    TimeRuntimeConfig { enabled: false, ..test_config() }
}

fn start_service(ntp: Arc<FakeNtpClient>, clock: Arc<FakeClock>) -> SyncTimeService {
    SyncTimeService::start_with(ntp, clock, test_config())
}

/// Drives the runtime until `predicate` holds: yields to let due tasks poll,
/// then advances simulated time in small steps to wake timers.
async fn run_until(predicate: impl Fn() -> bool) {
    for _ in 0..10_000 {
        if predicate() {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(StdDuration::from_millis(100)).await;
    }
    panic!("condition not met within simulated time budget");
}

/// Lets already-runnable tasks poll without advancing time.
async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn initial_sync_steps_clock_and_records_success() {
    let ntp = FakeNtpClient::new(vec![ntp_ok(12.5)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| {
        let status = service.status();
        status.last_action == TimeSyncAction::InitialStep
            && status.next_attempt_in_secs == Some(test_config().sync_interval_secs)
    })
    .await;
    assert_eq!(clock.set_calls(), 1);

    let status = service.status();
    assert_eq!(status.current_source, TimeSyncSource::Ntp);
    assert_eq!(status.sync_stage, TimeSyncStage::Initial);
    assert_eq!(status.last_action, TimeSyncAction::InitialStep);
    assert!(status.last_success_at.is_some());
    assert!(status.system_clock_synced);
    assert_eq!(status.next_attempt_in_secs, Some(test_config().sync_interval_secs));

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn query_failure_falls_back_then_succeeds_as_initial() {
    let ntp = FakeNtpClient::new(vec![ntp_err(), ntp_ok(8.0)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| service.status().last_action == TimeSyncAction::FallbackSystem).await;
    let failed = service.status();
    assert_eq!(failed.sync_stage, TimeSyncStage::Fallback);
    assert!(!failed.system_clock_synced);
    assert_eq!(failed.next_attempt_in_secs, Some(BACKOFF_INITIAL_SECS));

    run_until(|| {
        let status = service.status();
        status.last_action == TimeSyncAction::InitialStep && status.last_success_at.is_some()
    })
    .await;
    assert_eq!(clock.set_calls(), 1);
    let recovered = service.status();
    assert_eq!(recovered.current_source, TimeSyncSource::Ntp);
    // Still no recorded success before this attempt, so it stays "initial".
    assert_eq!(recovered.last_action, TimeSyncAction::InitialStep);
    assert!(recovered.system_clock_synced);

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn clock_set_failure_keeps_success_unset() {
    let ntp = FakeNtpClient::new(vec![ntp_ok(15.0), ntp_ok(1.0)]);
    let clock = FakeClock::new(true);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| service.status().last_action == TimeSyncAction::NtpSetFailed).await;
    let failed = service.status();
    assert_eq!(failed.sync_stage, TimeSyncStage::Error);
    assert!(failed.last_success_at.is_none());
    assert!(!failed.system_clock_synced);
    assert_eq!(failed.next_attempt_in_secs, Some(BACKOFF_INITIAL_SECS));

    // The clock recovers before the backoff retry fires.
    clock.set_fail(false);
    run_until(|| {
        let status = service.status();
        status.last_action == TimeSyncAction::InitialStep && status.last_success_at.is_some()
    })
    .await;
    assert_eq!(clock.set_calls(), 2);
    let status = service.status();
    // `is_initial` is still true, so the retry is labeled initial-step.
    assert_eq!(status.last_action, TimeSyncAction::InitialStep);
    assert!(status.last_success_at.is_some());

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn repeated_failures_back_off_up_to_cap() {
    let failures: Vec<io::Result<NtpQueryResult>> = (0..7).map(|_| ntp_err()).collect();
    let ntp = FakeNtpClient::new(failures);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock);

    run_until(|| {
        let status = service.status();
        status.last_action == TimeSyncAction::FallbackSystem
            && status.next_attempt_in_secs == Some(BACKOFF_MAX_SECS)
    })
    .await;
    let status = service.status();
    // Backoff sequence 5,10,20,40,80,160,320 -> capped at 300.
    assert_eq!(status.next_attempt_in_secs, Some(BACKOFF_MAX_SECS));
    assert_eq!(status.sync_stage, TimeSyncStage::Fallback);
    assert_eq!(ntp.query_count(), 7);

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn disable_parks_loop_and_reenable_queries_immediately() {
    let ntp = FakeNtpClient::new(vec![ntp_ok(5.0), ntp_ok(3.0)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| ntp.query_count() == 1).await;

    service.update_config(disabled_config());
    run_until(|| service.status().sync_stage == TimeSyncStage::Disabled).await;
    // Parked: advance far beyond the sync interval; no queries must fire.
    tokio::time::advance(StdDuration::from_secs(600)).await;
    settle().await;
    assert_eq!(ntp.query_count(), 1);
    assert_eq!(service.status().sync_stage, TimeSyncStage::Disabled);
    assert_eq!(service.status().next_attempt_in_secs, None);

    service.update_config(test_config());
    // Re-enable wakes the loop; first_run makes it query without waiting
    // for the interval. Only yield, do not advance time.
    for _ in 0..100 {
        if ntp.query_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(ntp.query_count(), 2);

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn config_change_wakes_pending_interval() {
    let ntp = FakeNtpClient::new(vec![ntp_ok(5.0), ntp_ok(3.0)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| ntp.query_count() == 1).await;

    let mut new_config = test_config();
    new_config.servers = vec!["other.pool.ntp.org".to_string()];
    service.update_config(new_config);

    // The pending 60s interval must be cut short: only yields, no advance.
    for _ in 0..100 {
        if ntp.query_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(ntp.query_count(), 2);

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn stop_cancels_and_no_further_queries_happen() {
    let ntp = FakeNtpClient::new(vec![ntp_ok(5.0)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| service.status().last_action == TimeSyncAction::InitialStep).await;
    service.stop().await;

    service.update_config(test_config());
    tokio::time::advance(StdDuration::from_secs(600)).await;
    settle().await;
    assert_eq!(ntp.query_count(), 1);
    assert_eq!(service.status().last_action, TimeSyncAction::InitialStep);

    // Stopping again is a no-op.
    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn sync_now_disabled_returns_error() {
    let ntp = FakeNtpClient::new(vec![]);
    let clock = FakeClock::new(false);
    let service = SyncTimeService::start_with(ntp.clone(), clock.clone(), disabled_config());

    assert!(matches!(service.sync_now(), Err(TimeSyncError::SyncDisabled)));

    service.update_config(test_config());
    assert!(service.sync_now().is_ok());

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn sync_now_triggers_immediate_query() {
    let ntp = FakeNtpClient::new(vec![ntp_ok(5.0), ntp_ok(3.0)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| ntp.query_count() == 1).await;

    // Manual trigger skips the 60s interval; only yields, no advance.
    service.sync_now().unwrap();
    for _ in 0..100 {
        if ntp.query_count() == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(ntp.query_count(), 2);

    // Second success: offset below threshold -> refresh.
    run_until(|| service.status().last_success_at.is_some()).await;
    let status = service.status();
    assert_eq!(status.last_action, TimeSyncAction::PeriodicRefresh);
    assert_eq!(status.sync_stage, TimeSyncStage::Steady);

    service.stop().await;
}

#[tokio::test(start_paused = true)]
async fn sync_now_clears_failure_backoff() {
    let ntp = FakeNtpClient::new(vec![ntp_err(), ntp_ok(4.0)]);
    let clock = FakeClock::new(false);
    let service = start_service(ntp.clone(), clock.clone());

    run_until(|| service.status().last_action == TimeSyncAction::FallbackSystem).await;

    service.sync_now().unwrap();
    run_until(|| service.status().last_success_at.is_some()).await;
    assert_eq!(ntp.query_count(), 2);
    assert_eq!(service.status().last_action, TimeSyncAction::InitialStep);

    service.stop().await;
}
