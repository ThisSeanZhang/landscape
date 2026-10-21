use std::{collections::HashMap, fs::File, io, path::Path, time::Instant};

use futures::TryStreamExt;
use landscape_common::config_service::geo::{
    GeoError, GeoFileCacheKey, GeoSiteSource, GeoSiteSourceConfig, GeoTaskPhase,
};
use landscape_core::geo_cache::{CacheWriteOutcome, SiteCacheStreamEvent, SiteRuleRow};
use landscape_protobuf::SiteSnapshotReader;
use reqwest::Client;
use tokio::sync::mpsc;
use tokio_util::io::{StreamReader, SyncIoBridge};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::GeoSiteService;
use crate::geo::download::{DownloadProgressReader, GeoDownloadError, download_to_sealed};
use crate::geo::raw_file::{raw_dat_path, remove_raw_dat};
use crate::geo::site_snapshot::{
    SiteSnapshotBuildSummary, build_adguard_snapshot_file, build_dat_snapshot_bytes,
    build_dat_snapshot_reader,
};
use crate::geo::storage::{geo_snapshot_path, geo_snapshot_source_path};
use crate::geo::{GeoCacheApplyResult, GeoTaskMode};

const SNAPSHOT_CACHE_BATCH: usize = 500;
const SNAPSHOT_CACHE_CHANNEL_SIZE: usize = 8;

impl GeoSiteService {
    async fn download_dat_snapshot(
        &self,
        source_id: Uuid,
        url: &str,
        snapshot_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<SiteSnapshotBuildSummary, GeoError> {
        // Downloads run at most once a day per source, so connection reuse
        // across tasks would not pay for a shared client.
        let client = Client::new();
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| GeoError::RawDatReadFailed(format!("request {url} error: {e}")))?;
        if !response.status().is_success() {
            return Err(GeoError::RawDatReadFailed(format!(
                "{url} returned HTTP {}",
                response.status()
            )));
        }
        let bytes_total = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());

        self.tasks.advance(source_id, GeoTaskPhase::Parsing);
        let stream = response.bytes_stream().map_err(io::Error::other);
        let async_reader = StreamReader::new(stream);
        let sync_reader = SyncIoBridge::new(async_reader);
        let registry = self.tasks.clone();
        let cancel_in_worker = cancel.clone();
        let path = snapshot_path.to_path_buf();
        let result = tokio::task::spawn_blocking(move || {
            let reader = DownloadProgressReader::new(
                sync_reader,
                registry,
                source_id,
                bytes_total,
                cancel_in_worker.clone(),
            );
            build_dat_snapshot_reader(reader, &path, source_id, &cancel_in_worker)
        })
        .await
        .map_err(|e| GeoError::RawDatReadFailed(format!("snapshot worker join failed: {e}")))?;
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        result
    }

    async fn download_adguard_snapshot(
        &self,
        source_id: Uuid,
        url: &str,
        key: &str,
        snapshot_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<SiteSnapshotBuildSummary, GeoError> {
        let source_path = geo_snapshot_source_path("site", source_id);
        let sealed = download_to_sealed(source_id, url, &source_path, &self.tasks, cancel)
            .await
            .map_err(|error| match error {
                GeoDownloadError::Cancelled => GeoError::TaskCancelled,
                error => GeoError::RawDatReadFailed(format!("download {url} failed: {error}")),
            })?;
        if cancel.is_cancelled() {
            sealed.abort();
            return Err(GeoError::TaskCancelled);
        }

        self.tasks.advance(source_id, GeoTaskPhase::Verifying);
        self.tasks.advance(source_id, GeoTaskPhase::Parsing);
        let tmp_path = sealed.path().to_path_buf();
        let final_path = snapshot_path.to_path_buf();
        let key = key.to_string();
        let cancel_in_worker = cancel.clone();
        let result = tokio::task::spawn_blocking(move || {
            build_adguard_snapshot_file(&tmp_path, &final_path, source_id, &key, &cancel_in_worker)
        })
        .await
        .map_err(|e| GeoError::RawDatReadFailed(format!("snapshot worker join failed: {e}")))?;
        sealed.abort();

        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        result
    }

    async fn ensure_snapshot_from_legacy_raw(
        &self,
        config: &GeoSiteSourceConfig,
        snapshot_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<bool, GeoError> {
        if snapshot_path.exists() {
            remove_raw_dat("site", config.id);
            return Ok(true);
        }
        let raw_path = raw_dat_path("site", config.id);
        if !raw_path.exists() {
            return Ok(false);
        }

        self.tasks.advance(config.id, GeoTaskPhase::Verifying);
        self.tasks.advance(config.id, GeoTaskPhase::Parsing);
        let snapshot_path = snapshot_path.to_path_buf();
        let source_id = config.id;
        let source = config.source.clone();
        let cancel_in_worker = cancel.clone();
        let raw_path_in_worker = raw_path.clone();
        let result = tokio::task::spawn_blocking(move || match source {
            GeoSiteSource::AdguardHome { key, .. } => build_adguard_snapshot_file(
                &raw_path_in_worker,
                &snapshot_path,
                source_id,
                &key,
                &cancel_in_worker,
            ),
            GeoSiteSource::Url { .. } => {
                let file = File::open(&raw_path_in_worker).map_err(|e| {
                    GeoError::RawDatReadFailed(format!(
                        "open legacy raw file {raw_path_in_worker:?}: {e}"
                    ))
                })?;
                build_dat_snapshot_reader(file, &snapshot_path, source_id, &cancel_in_worker)
            }
            GeoSiteSource::Direct { .. } => Err(GeoError::RawDatNotReady),
        })
        .await
        .map_err(|e| GeoError::RawDatReadFailed(format!("snapshot worker join failed: {e}")))?;

        match result {
            Ok(summary) => {
                remove_raw_dat("site", config.id);
                tracing::info!(
                    "migrated legacy geo site source '{}' to snapshot ({} entries)",
                    config.name,
                    summary.entries
                );
                Ok(true)
            }
            Err(GeoError::TaskCancelled) => Err(GeoError::TaskCancelled),
            Err(error) => {
                tracing::warn!(
                    "migrate legacy geo site source '{}' from {:?} failed: {}",
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
        let reader = tokio::task::spawn_blocking(move || SiteSnapshotReader::open(&path))
            .await
            .map_err(|e| GeoError::RawDatReadFailed(format!("snapshot worker join failed: {e}")))?
            .map_err(|e| {
                GeoError::RawDatReadFailed(format!("open snapshot {snapshot_path:?} failed: {e}"))
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
            let producer_result = producer.await.map_err(|e| {
                GeoError::RawDatReadFailed(format!("snapshot worker join failed: {e}"))
            })?;
            producer_result?;
            let outcomes = writer?;

            for (key, outcome) in outcomes {
                let cache_key = GeoFileCacheKey { name: name.to_string(), key };
                match outcome {
                    CacheWriteOutcome::Unchanged => result.unchanged_keys += 1,
                    CacheWriteOutcome::Inserted | CacheWriteOutcome::Updated => {
                        result.changed_keys.insert(cache_key);
                    }
                }
            }
        }

        for key in stale_keys {
            let cache_key = GeoFileCacheKey { name: name.to_string(), key };
            if self.delete_cache_key(&cache_key).await {
                result.changed_keys.insert(cache_key);
                result.deleted_keys += 1;
            }
        }

        Ok(result)
    }

    async fn build_upload_snapshot(
        &self,
        source_id: Uuid,
        snapshot_path: &Path,
        file_bytes: Vec<u8>,
        cancel: &CancellationToken,
    ) -> Result<SiteSnapshotBuildSummary, GeoError> {
        self.tasks.advance(source_id, GeoTaskPhase::Parsing);
        let path = snapshot_path.to_path_buf();
        let cancel_in_worker = cancel.clone();
        let result = tokio::task::spawn_blocking(move || {
            build_dat_snapshot_bytes(&file_bytes, &path, source_id, &cancel_in_worker)
        })
        .await
        .map_err(|e| GeoError::RawDatReadFailed(format!("snapshot worker join failed: {e}")))?;
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        result
    }

    pub(super) async fn run_geo_task(
        &self,
        config: GeoSiteSourceConfig,
        mode: GeoTaskMode,
        cancel: &CancellationToken,
    ) {
        let source_id = config.id;
        let snapshot_path = geo_snapshot_path("site", source_id);

        if matches!(mode, GeoTaskMode::RestoreOnly) {
            match self.ensure_snapshot_from_legacy_raw(&config, &snapshot_path, cancel).await {
                Ok(false) => return,
                Err(GeoError::TaskCancelled) => return,
                Err(e) => {
                    tracing::warn!("restore geo site source '{}' failed: {}", config.name, e);
                    return;
                }
                Ok(true) => {}
            }

            self.tasks.advance(source_id, GeoTaskPhase::Applying);
            match self.apply_snapshot(&config.name, &snapshot_path, true, cancel).await {
                Ok(apply_result) => {
                    tracing::info!(
                        "restored geo site cache '{}' from snapshot {:?}",
                        config.name,
                        snapshot_path
                    );
                    self.notify_geo_changes(apply_result.changed_keys).await;
                }
                Err(GeoError::TaskCancelled) => {}
                Err(e) => {
                    tracing::warn!(
                        "restore geo site cache '{}' from snapshot {:?} failed: {}",
                        config.name,
                        snapshot_path,
                        e
                    );
                }
            }
            return;
        }

        let build_result = match mode {
            GeoTaskMode::Download => {
                let url = match &config.source {
                    GeoSiteSource::Url { url, .. } | GeoSiteSource::AdguardHome { url, .. } => {
                        url.clone()
                    }
                    _ => return,
                };
                tracing::debug!("download file: {}", url);
                let time = Instant::now();
                let result = match &config.source {
                    GeoSiteSource::AdguardHome { key, .. } => {
                        self.download_adguard_snapshot(source_id, &url, key, &snapshot_path, cancel)
                            .await
                    }
                    _ => self.download_dat_snapshot(source_id, &url, &snapshot_path, cancel).await,
                };
                match result {
                    Ok(summary) => {
                        tracing::debug!(
                            "handle file done: {}, time: {}ms, entries: {}",
                            url,
                            time.elapsed().as_millis(),
                            summary.entries
                        );
                        summary
                    }
                    Err(GeoError::TaskCancelled) => {
                        tracing::info!("refresh geo site source {} cancelled", config.name);
                        return;
                    }
                    Err(e) => {
                        tracing::error!("refresh geo site source {} error: {}", config.name, e);
                        return;
                    }
                }
            }
            GeoTaskMode::Upload(file_bytes) => {
                if matches!(config.source, GeoSiteSource::Direct { .. }) {
                    tracing::warn!(
                        "upload is not supported for direct geo site source '{}'",
                        config.name
                    );
                    return;
                }
                match self
                    .build_upload_snapshot(source_id, &snapshot_path, file_bytes, cancel)
                    .await
                {
                    Ok(summary) => summary,
                    Err(GeoError::TaskCancelled) => return,
                    Err(e) => {
                        tracing::error!(
                            "build upload snapshot for geo site '{}' failed: {}",
                            config.name,
                            e
                        );
                        return;
                    }
                }
            }
            GeoTaskMode::RestoreOnly => unreachable!(),
        };

        if cancel.is_cancelled() {
            return;
        }

        // New snapshots are the persistent authority. Old raw files are
        // removed after a successful conversion.
        remove_raw_dat("site", source_id);

        self.tasks.advance(source_id, GeoTaskPhase::Applying);
        let apply_result =
            match self.apply_snapshot(&config.name, &snapshot_path, false, cancel).await {
                Ok(result) => result,
                Err(GeoError::TaskCancelled) => return,
                Err(e) => {
                    tracing::error!(
                        "apply geo site snapshot '{}' ({} entries) failed: {}",
                        config.name,
                        build_result.entries,
                        e
                    );
                    GeoCacheApplyResult::default()
                }
            };

        match self.store.bump_refresh_schedule(source_id).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(
                    "geo site config {} deleted during task; skip schedule update",
                    config.name
                );
            }
            Err(e) => {
                tracing::warn!("bump geo site refresh schedule {} failed: {}", config.name, e);
            }
        }

        tracing::debug!(
            "apply geo site done: name={} changed_keys={} unchanged_keys={} deleted_keys={}",
            config.name,
            apply_result.changed_keys.len(),
            apply_result.unchanged_keys,
            apply_result.deleted_keys,
        );
        self.notify_geo_changes(apply_result.changed_keys).await;
    }
}

pub(super) fn stream_snapshot_cache_events(
    reader: SiteSnapshotReader,
    changed: HashMap<String, String>,
    tx: mpsc::Sender<SiteCacheStreamEvent>,
    cancel: CancellationToken,
) -> Result<(), GeoError> {
    let mut entries: Vec<(String, String)> = changed.into_iter().collect();
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for (key, content_hash) in entries {
        if cancel.is_cancelled() {
            return Err(GeoError::TaskCancelled);
        }
        send_site_cache_event(&tx, SiteCacheStreamEvent::Begin { key: key.clone(), content_hash })?;

        let mut key_reader = reader.open_key(&key).map_err(|e| {
            GeoError::RawDatReadFailed(format!("open snapshot key {key} failed: {e}"))
        })?;
        let mut batch = Vec::with_capacity(SNAPSHOT_CACHE_BATCH);
        loop {
            if cancel.is_cancelled() {
                return Err(GeoError::TaskCancelled);
            }
            let Some(rule) = key_reader.next_rule().map_err(|e| {
                GeoError::RawDatReadFailed(format!("read snapshot key {key} failed: {e}"))
            })?
            else {
                break;
            };
            batch.push(SiteRuleRow::new(
                rule.match_type,
                rule.value,
                rule.attributes.into_iter().collect(),
            ));
            if batch.len() >= SNAPSHOT_CACHE_BATCH {
                send_site_cache_event(
                    &tx,
                    SiteCacheStreamEvent::Rules(std::mem::take(&mut batch)),
                )?;
                batch = Vec::with_capacity(SNAPSHOT_CACHE_BATCH);
            }
        }
        if !batch.is_empty() {
            send_site_cache_event(&tx, SiteCacheStreamEvent::Rules(batch))?;
        }
        send_site_cache_event(&tx, SiteCacheStreamEvent::End)?;
    }
    Ok(())
}

fn send_site_cache_event(
    tx: &mpsc::Sender<SiteCacheStreamEvent>,
    event: SiteCacheStreamEvent,
) -> Result<(), GeoError> {
    tx.blocking_send(event)
        .map_err(|_| GeoError::RawDatReadFailed("geo site cache stream closed".to_string()))
}
