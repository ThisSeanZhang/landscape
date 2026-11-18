use std::{path::PathBuf, time::Duration};

use super::{state::MetricStatus, supervisor::first_attempt_complete};
use landscape_common::{
    memtrack::{
        MemoryHistory,
        sampler::{DEFAULT_CAPACITY, DEFAULT_SAMPLE_INTERVAL},
    },
    self_monitor::memory::{MemHistoryQueryParams, MemHistoryResponse},
    service::ServiceStatus,
    sys_config::SelfMonitorRuntimeConfig,
};
use landscape_metric::self_monitor_store::{MemRecording, start_memory_recording};
use tokio::sync::{Mutex, oneshot, watch};
use tokio_util::sync::CancellationToken;

pub(super) struct SelfMonitorService {
    home: PathBuf,
    desired: watch::Receiver<SelfMonitorRuntimeConfig>,
    pub(super) history: MemoryHistory,
    pub(super) status: MetricStatus,
    recording: Mutex<Option<MemRecording>>,
}

impl SelfMonitorService {
    pub(super) fn new(home: PathBuf, desired: watch::Receiver<SelfMonitorRuntimeConfig>) -> Self {
        Self {
            home,
            desired,
            history: MemoryHistory::new(DEFAULT_CAPACITY),
            status: MetricStatus::default(),
            recording: Mutex::new(None),
        }
    }

    pub(super) async fn run(&self, stop: &CancellationToken, ready: oneshot::Sender<()>) {
        if cfg!(feature = "mem-track") {
            tokio::join!(
                Self::sample(self.history.clone(), self.desired.clone(), stop),
                self.record(stop, ready)
            );
        } else {
            let _ = ready.send(());
        }
    }

    async fn sample(
        history: MemoryHistory,
        mut desired: watch::Receiver<SelfMonitorRuntimeConfig>,
        stop: &CancellationToken,
    ) {
        let mut tick = tokio::time::interval(DEFAULT_SAMPLE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let enabled = desired.borrow_and_update().enabled;
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                change = desired.changed() => {
                    if change.is_err() { break; }
                }
                _ = tick.tick(), if enabled => history.sample(),
            }
        }
    }

    async fn record(&self, stop: &CancellationToken, ready: oneshot::Sender<()>) {
        let mut desired = self.desired.clone();
        let mut ready = Some(ready);
        while !stop.is_cancelled() && desired.has_changed().is_ok() {
            let config = desired.borrow_and_update().clone();
            let record =
                cfg!(feature = "metric-persistent") && config.enabled && config.history_enabled;
            let mut retry = false;
            if record {
                self.status.set(ServiceStatus::Staring);
                let mut slot = self.recording.lock().await;
                if let Some(active) = slot.as_mut() {
                    active.spawn_recorder(config.retention_days);
                } else {
                    *slot = start_memory_recording(self.home.clone(), config.retention_days).await;
                    retry = slot.is_none();
                }
            }
            self.status.set(if retry {
                ServiceStatus::Failed
            } else if config.enabled {
                ServiceStatus::Running
            } else {
                ServiceStatus::Stop
            });
            first_attempt_complete(&mut ready);
            tokio::select! {
                _ = stop.cancelled() => (),
                _ = desired.wait_for(|value| value != &config) => (),
                _ = tokio::time::sleep(Duration::from_secs(30)), if retry => (),
            }
            if record && !retry {
                self.status.set(ServiceStatus::Stopping);
                if let Some(active) = self.recording.lock().await.as_mut() {
                    active.stop_recorder().await;
                }
            }
        }
        self.status.set(ServiceStatus::Stop);
    }

    pub(super) async fn query_history(&self, params: &MemHistoryQueryParams) -> MemHistoryResponse {
        let mut slot = self.recording.lock().await;
        if slot.is_none() {
            *slot = MemRecording::open_existing(&self.home).await;
        }
        match slot.as_ref() {
            Some(active) => active.query_history(params).await,
            None => MemHistoryResponse::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::sys_config::{LandscapeSelfMonitorConfig, RuntimeConfigSource};

    fn start(
        home: PathBuf,
        rx: watch::Receiver<SelfMonitorRuntimeConfig>,
    ) -> (std::sync::Arc<SelfMonitorService>, CancellationToken, tokio::task::JoinHandle<()>) {
        let monitor = std::sync::Arc::new(SelfMonitorService::new(home, rx));
        let service = monitor.clone();
        let stop = CancellationToken::new();
        let token = stop.clone();
        let (ready, _) = oneshot::channel();
        let task = tokio::spawn(async move { service.run(&token, ready).await });
        (monitor, stop, task)
    }

    #[tokio::test]
    async fn history_only_opens_its_database_when_both_features_are_available() {
        let dir = tempfile::tempdir().unwrap();
        let config = LandscapeSelfMonitorConfig::default().build_runtime();
        let (_tx, rx) = watch::channel(config);
        let (monitor, stop, task) = start(dir.path().into(), rx);
        let metric_dir = dir.path().join(landscape_common::LANDSCAPE_METRIC_DIR_NAME);
        if cfg!(all(feature = "mem-track", feature = "metric-persistent")) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while monitor.recording.lock().await.is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            for file in metric_dir.read_dir().unwrap() {
                assert!(file.unwrap().file_name().to_string_lossy().contains("_memory.sqlite"));
            }
        } else {
            tokio::task::yield_now().await;
            assert!(!metric_dir.exists());
        }
        stop.cancel();
        task.await.unwrap();
    }

    #[cfg(all(feature = "mem-track", feature = "metric-persistent"))]
    #[tokio::test]
    async fn disabled_recording_can_read_previous_minutes_after_restart() {
        use landscape_common::{LANDSCAPE_METRIC_DIR_NAME, self_monitor::memory::MemMinuteRecord};
        use landscape_metric::self_monitor_store::MemMetricStore;

        let dir = tempfile::tempdir().unwrap();
        let config =
            LandscapeSelfMonitorConfig { history_enabled: Some(false), ..Default::default() }
                .build_runtime();
        let (_tx, rx) = watch::channel(config);
        let (monitor, stop, task) = start(dir.path().into(), rx.clone());
        let query = MemHistoryQueryParams {
            start_time: 60_000,
            end_time: 120_000,
            ..Default::default()
        };
        assert!(monitor.query_history(&query).await.timestamps.is_empty());
        let path = dir.path().join(LANDSCAPE_METRIC_DIR_NAME);
        assert!(!path.exists());
        stop.cancel();
        task.await.unwrap();

        std::fs::create_dir(&path).unwrap();
        let db = MemMetricStore::open(&path).await.unwrap();
        assert!(
            db.record_minute(&[MemMinuteRecord {
                minute_ts: 60_000,
                subsystem: "dns".into(),
                live_avg_bytes: 10,
                live_max_bytes: 10,
                alloc_delta_bytes: 10,
                free_delta_bytes: 0
            }])
            .await
        );
        db.close().await;
        let (monitor, stop, task) = start(dir.path().into(), rx);
        assert_eq!(monitor.query_history(&query).await.timestamps, [60_000]);
        stop.cancel();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn sampling_follows_its_own_settings_and_build_capability() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = LandscapeSelfMonitorConfig {
            enabled: Some(false),
            history_enabled: Some(false),
            ..Default::default()
        }
        .build_runtime();
        let (tx, rx) = watch::channel(config.clone());
        let (monitor, stop, task) = start(dir.path().into(), rx);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(monitor.history.is_empty());
        config.enabled = true;
        tx.send_replace(config.clone());
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(!monitor.history.is_empty(), cfg!(feature = "mem-track"));
        config.enabled = false;
        tx.send_replace(config);
        tokio::task::yield_now().await;
        let count = monitor.history.len();
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(monitor.history.len(), count);
        assert_eq!(dir.path().read_dir().unwrap().count(), 0);
        stop.cancel();
        task.await.unwrap();
    }
}
