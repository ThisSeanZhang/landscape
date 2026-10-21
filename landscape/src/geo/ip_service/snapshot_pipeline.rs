use std::{collections::HashMap, fs::File, path::Path, time::Instant};

use landscape_common::config_service::geo::{
    GeoError, GeoFileCacheKey, GeoIpSource, GeoIpSourceConfig, GeoTaskPhase,
};
use landscape_core::geo_cache::{CacheWriteOutcome, IpCacheStreamEvent, IpCidrRow};
use landscape_protobuf::IpSnapshotReader;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::GeoIpService;
use crate::geo::download::{GeoDownloadError, download_to_sealed};
use crate::geo::ip_snapshot::build_ip_snapshot_reader;
use crate::geo::raw_file::raw_dat_path;
use crate::geo::storage::{geo_snapshot_path, write_bytes_to_sealed};
use crate::geo::{GeoCacheApplyResult, GeoTaskMode};

const SNAPSHOT_CACHE_BATCH: usize = 500;
const SNAPSHOT_CACHE_CHANNEL_SIZE: usize = 8;

impl GeoIpService {
    pub(super) async fn run_geo_task(
        &self,
        config: GeoIpSourceConfig,
        mode: GeoTaskMode,
        cancel: &CancellationToken,
    ) {
        let source_id = config.id;
        let snapshot_path = geo_snapshot_path("ip", source_id);

        if matches!(mode, GeoTaskMode::RestoreOnly) {
            match self.ensure_snapshot_from_legacy_raw(&config, &snapshot_path, cancel).await {
                Ok(false) => return,
                Err(GeoError::TaskCancelled) => return,
                Err(error) => {
                    tracing::warn!("restore geo ip source '{}' failed: {}", config.name, error);
                    return;
                }
                Ok(true) => {}
            }

            self.tasks.advance(source_id, GeoTaskPhase::Applying);
            match self.apply_snapshot(&config.name, &snapshot_path, true, cancel).await {
                Ok(result) => {
                    tracing::info!(
                        "restored geo ip cache '{}' from snapshot {:?}",
                        config.name,
                        snapshot_path
                    );
                    self.notify_dst_ip_updated(result.changed_keys);
                }
                Err(GeoError::TaskCancelled) => {}
                Err(error) => {
                    tracing::warn!(
                        "restore geo ip cache '{}' from snapshot {:?} failed: {}",
                        config.name,
                        snapshot_path,
                        error
                    );
                }
            }
            return;
        }

        if matches!(&mode, GeoTaskMode::Upload(_))
            && matches!(&config.source, GeoIpSource::Direct { .. })
        {
            tracing::warn!("upload is not supported for direct geo ip source '{}'", config.name);
            return;
        }
        let (format, txt_key) = match &config.source {
            GeoIpSource::Url { format, txt_key, .. } => (format.clone(), txt_key.clone()),
            GeoIpSource::Direct { .. } => return,
        };
        let dat_path = raw_dat_path("ip", source_id);

        let sealed = match mode {
            GeoTaskMode::Download => {
                let url = match &config.source {
                    GeoIpSource::Url { url, .. } => url.clone(),
                    GeoIpSource::Direct { .. } => return,
                };
                tracing::debug!("download file: {}", url);
                let started = Instant::now();
                match download_to_sealed(source_id, &url, &dat_path, &self.tasks, cancel).await {
                    Ok(sealed) => {
                        tracing::debug!(
                            "download file done: {}, time: {}s",
                            url,
                            started.elapsed().as_secs()
                        );
                        sealed
                    }
                    Err(GeoDownloadError::Cancelled) => {
                        tracing::info!("refresh geo ip source {} cancelled", config.name);
                        return;
                    }
                    Err(error) => {
                        let error = GeoError::IpSourceRequestFailed(error.to_string());
                        tracing::error!("refresh geo ip source {} error: {}", config.name, error);
                        return;
                    }
                }
            }
            GeoTaskMode::Upload(file_bytes) => {
                match write_bytes_to_sealed(&dat_path, &file_bytes) {
                    Ok(sealed) => sealed,
                    Err(error) => {
                        tracing::error!("persist raw geo ip file {:?} failed: {}", dat_path, error);
                        return;
                    }
                }
            }
            GeoTaskMode::RestoreOnly => unreachable!(),
        };

        if cancel.is_cancelled() {
            sealed.abort();
            return;
        }

        self.tasks.advance(source_id, GeoTaskPhase::Verifying);
        self.tasks.advance(source_id, GeoTaskPhase::Parsing);
        let sealed_path = sealed.path().to_path_buf();
        let build_path = snapshot_path.clone();
        let cancel_in_worker = cancel.clone();
        let result = tokio::task::spawn_blocking(move || {
            let file = File::open(&sealed_path).map_err(|error| {
                GeoError::RawDatReadFailed(format!("open downloaded geo ip file: {error}"))
            })?;
            build_ip_snapshot_reader(
                file,
                &build_path,
                source_id,
                &format,
                txt_key.as_deref(),
                &cancel_in_worker,
            )
        })
        .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                sealed.abort();
                tracing::error!(
                    "refresh geo ip source {} snapshot worker failed: {}",
                    config.name,
                    error
                );
                return;
            }
        };

        let summary = match result {
            Ok(summary) => summary,
            Err(GeoError::TaskCancelled) => {
                sealed.abort();
                return;
            }
            Err(error) => {
                sealed.abort();
                tracing::error!("refresh geo ip source {} error: {}", config.name, error);
                return;
            }
        };
        if cancel.is_cancelled() {
            sealed.abort();
            return;
        }

        // Snapshot is the runtime authority, but keep the raw file for now as a
        // rollback/legacy fallback.
        if let Err(error) = sealed.commit() {
            tracing::warn!("persist raw geo ip file {:?} failed: {}", dat_path, error);
        }

        self.tasks.advance(source_id, GeoTaskPhase::Applying);
        let apply_result =
            match self.apply_snapshot(&config.name, &snapshot_path, false, cancel).await {
                Ok(result) => result,
                Err(GeoError::TaskCancelled) => return,
                Err(error) => {
                    tracing::error!(
                        "apply geo ip snapshot '{}' ({} entries) failed: {}",
                        config.name,
                        summary.entries,
                        error
                    );
                    GeoCacheApplyResult::default()
                }
            };

        match self.store.bump_refresh_schedule(source_id).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    "geo ip config {} deleted during task; skip schedule update",
                    config.name
                );
            }
            Err(error) => {
                tracing::error!("bump geo ip refresh schedule {} failed: {}", config.name, error);
            }
        }

        tracing::debug!(
            "apply geo ip done: name={} entries={} valid_lines={} skipped_lines={} changed_keys={} unchanged_keys={} deleted_keys={}",
            config.name,
            summary.entries,
            summary.valid_lines,
            summary.skipped_lines,
            apply_result.changed_keys.len(),
            apply_result.unchanged_keys,
            apply_result.deleted_keys,
        );
        self.notify_dst_ip_updated(apply_result.changed_keys);
    }

    async fn ensure_snapshot_from_legacy_raw(
        &self,
        config: &GeoIpSourceConfig,
        snapshot_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<bool, GeoError> {
        if snapshot_path.exists() {
            return Ok(true);
        }
        let raw_path = raw_dat_path("ip", config.id);
        if !raw_path.exists() {
            return Ok(false);
        }
        let (format, txt_key) = match &config.source {
            GeoIpSource::Url { format, txt_key, .. } => (format.clone(), txt_key.clone()),
            GeoIpSource::Direct { .. } => return Ok(false),
        };

        self.tasks.advance(config.id, GeoTaskPhase::Verifying);
        self.tasks.advance(config.id, GeoTaskPhase::Parsing);
        let snapshot_path = snapshot_path.to_path_buf();
        let source_id = config.id;
        let cancel_in_worker = cancel.clone();
        let raw_path_in_worker = raw_path.clone();
        let result = tokio::task::spawn_blocking(move || {
            let file = File::open(&raw_path_in_worker).map_err(|error| {
                GeoError::RawDatReadFailed(format!(
                    "open legacy raw file {raw_path_in_worker:?}: {error}"
                ))
            })?;
            build_ip_snapshot_reader(
                file,
                &snapshot_path,
                source_id,
                &format,
                txt_key.as_deref(),
                &cancel_in_worker,
            )
        })
        .await
        .map_err(|error| {
            GeoError::RawDatReadFailed(format!("snapshot worker join failed: {error}"))
        })?;

        match result {
            Ok(summary) => {
                tracing::info!(
                    "migrated legacy geo ip source '{}' to snapshot ({} entries)",
                    config.name,
                    summary.entries
                );
                Ok(true)
            }
            Err(GeoError::TaskCancelled) => Err(GeoError::TaskCancelled),
            Err(error) => {
                tracing::warn!(
                    "migrate legacy geo ip source '{}' from {:?} failed: {}",
                    config.name,
                    raw_path,
                    error
                );
                Err(error)
            }
        }
    }

    async fn apply_snapshot(
        &self,
        name: &str,
        snapshot_path: &Path,
        skip_empty: bool,
        cancel: &CancellationToken,
    ) -> Result<GeoCacheApplyResult, GeoError> {
        let path = snapshot_path.to_path_buf();
        let reader = tokio::task::spawn_blocking(move || IpSnapshotReader::open(&path))
            .await
            .map_err(|error| {
                GeoError::RawDatReadFailed(format!("snapshot worker join failed: {error}"))
            })?
            .map_err(|error| {
                GeoError::RawDatReadFailed(format!(
                    "open snapshot {snapshot_path:?} failed: {error}"
                ))
            })?;

        let new_hashes = reader.index().content_hashes_hex();
        if skip_empty && new_hashes.is_empty() {
            return Ok(GeoCacheApplyResult::default());
        }

        let old_hashes = self.cache.entry_hashes_for_name(name).await?;
        let mut changed = HashMap::new();
        for (key, hash) in &new_hashes {
            if old_hashes.get(key) != Some(hash) {
                changed.insert(key.clone(), hash.clone());
            }
        }
        let stale_keys: Vec<String> =
            old_hashes.keys().filter(|key| !new_hashes.contains_key(*key)).cloned().collect();

        let mut result = GeoCacheApplyResult::default();
        if !changed.is_empty() {
            let (tx, rx) = mpsc::channel(SNAPSHOT_CACHE_CHANNEL_SIZE);
            let cancel_in_worker = cancel.clone();
            let producer = tokio::task::spawn_blocking(move || {
                stream_snapshot_cache_events(reader, changed, tx, cancel_in_worker)
            });
            let writer = self.cache.replace_stream(name, rx).await;
            let producer_result = producer.await.map_err(|error| {
                GeoError::RawDatReadFailed(format!("snapshot worker join failed: {error}"))
            })?;
            producer_result?;
            let outcomes = writer?;

            for (key, outcome) in outcomes {
                match outcome {
                    CacheWriteOutcome::Unchanged => result.unchanged_keys += 1,
                    CacheWriteOutcome::Inserted | CacheWriteOutcome::Updated => {
                        result.changed_keys.insert(GeoFileCacheKey { name: name.to_string(), key });
                    }
                }
            }
        }

        for key in stale_keys {
            let cache_key = GeoFileCacheKey { name: name.to_string(), key };
            if self.cache.delete_by_name(&cache_key.name, &cache_key.key).await? {
                result.changed_keys.insert(cache_key);
                result.deleted_keys += 1;
            }
        }

        Ok(result)
    }
}

pub(super) fn stream_snapshot_cache_events(
    reader: IpSnapshotReader,
    changed: HashMap<String, String>,
    tx: mpsc::Sender<IpCacheStreamEvent>,
    cancel: CancellationToken,
) -> Result<(), GeoError> {
    let mut entries: Vec<(String, String)> = changed.into_iter().collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for (key, content_hash) in entries {
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        send_ip_cache_event(&tx, IpCacheStreamEvent::Begin { key: key.clone(), content_hash })?;

        let mut key_reader = reader.open_key(&key).map_err(|error| {
            GeoError::RawDatReadFailed(format!("open snapshot key {key} failed: {error}"))
        })?;
        let mut batch = Vec::with_capacity(SNAPSHOT_CACHE_BATCH);
        loop {
            if cancel.is_cancelled() {
                return Err(GeoError::TaskCancelled);
            }
            let Some(cidr) = key_reader.next_cidr().map_err(|error| {
                GeoError::RawDatReadFailed(format!("read snapshot key {key} failed: {error}"))
            })?
            else {
                break;
            };
            batch.push(IpCidrRow { network: cidr.ip, prefix_len: cidr.prefix as u8 });
            if batch.len() >= SNAPSHOT_CACHE_BATCH {
                send_ip_cache_event(&tx, IpCacheStreamEvent::Cidrs(std::mem::take(&mut batch)))?;
                batch = Vec::with_capacity(SNAPSHOT_CACHE_BATCH);
            }
        }
        if !batch.is_empty() {
            send_ip_cache_event(&tx, IpCacheStreamEvent::Cidrs(batch))?;
        }
        send_ip_cache_event(&tx, IpCacheStreamEvent::End)?;
    }
    Ok(())
}

fn send_ip_cache_event(
    tx: &mpsc::Sender<IpCacheStreamEvent>,
    event: IpCacheStreamEvent,
) -> Result<(), GeoError> {
    tx.blocking_send(event)
        .map_err(|_| GeoError::RawDatReadFailed("geo ip cache stream closed".to_string()))
}
