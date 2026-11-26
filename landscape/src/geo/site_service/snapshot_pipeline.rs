use std::{collections::HashMap, path::Path, time::Instant};

use landscape_common::config_service::geo::{
    GeoError, GeoFileCacheKey, GeoSiteSource, GeoSiteSourceConfig, GeoTaskPhase,
};
use landscape_core::geo_cache::{CacheWriteOutcome, SiteCacheStreamEvent, SiteRuleRow};
use landscape_protobuf::SiteSnapshotReader;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::GeoSiteService;
use crate::geo::child::{self, BuildKind, BuildRequest};
use crate::geo::download::{GeoDownloadError, download_to_sealed};
use crate::geo::raw_file::raw_dat_path;
use crate::geo::storage::{geo_snapshot_path, write_bytes_to_sealed};
use crate::geo::{GeoCacheApplyResult, GeoTaskMode};

const SNAPSHOT_CACHE_BATCH: usize = 500;
const SNAPSHOT_CACHE_CHANNEL_SIZE: usize = 4;

impl GeoSiteService {
    pub(super) async fn run_geo_task(
        &self,
        config: GeoSiteSourceConfig,
        mode: GeoTaskMode,
        cancel: &CancellationToken,
    ) {
        let source_id = config.id;
        let snapshot_path = geo_snapshot_path("site", source_id);
        let raw_path = raw_dat_path("site", source_id);

        if matches!(mode, GeoTaskMode::RestoreOnly) {
            match self.ensure_snapshot(&config, &raw_path, &snapshot_path, cancel).await {
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

        // Stage 1 - fetch. The raw file is this stage's output, so it is
        // committed as soon as the bytes are on disk: a failed conversion must
        // not force another download.
        match mode {
            GeoTaskMode::Download => {
                let url = match &config.source {
                    GeoSiteSource::Url { url, .. } | GeoSiteSource::AdguardHome { url, .. } => {
                        url.clone()
                    }
                    _ => return,
                };
                tracing::debug!("download file: {}", url);
                let time = Instant::now();
                match download_to_sealed(source_id, &url, &raw_path, &self.tasks, cancel).await {
                    Ok(sealed) => {
                        tracing::debug!(
                            "handle file done: {}, time: {}ms",
                            url,
                            time.elapsed().as_millis()
                        );
                        if let Err(e) = sealed.commit() {
                            tracing::error!(
                                "persist raw geo site file {:?} failed: {}",
                                raw_path,
                                e
                            );
                            return;
                        }
                    }
                    Err(GeoDownloadError::Cancelled) => {
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
                let sealed = match write_bytes_to_sealed(&raw_path, &file_bytes) {
                    Ok(sealed) => sealed,
                    Err(e) => {
                        tracing::error!(
                            "persist uploaded geo site file {:?} failed: {}",
                            raw_path,
                            e
                        );
                        return;
                    }
                };
                if let Err(e) = sealed.commit() {
                    tracing::error!("persist raw geo site file {:?} failed: {}", raw_path, e);
                    return;
                }
            }
            GeoTaskMode::RestoreOnly => unreachable!(),
        }

        if cancel.is_cancelled() {
            return;
        }

        // Stage 2 - build. Runs in a child process: the decode allocates
        // millions of short-lived strings and its heap must not become part of
        // the daemon's.
        self.tasks.advance(source_id, GeoTaskPhase::Verifying);
        self.tasks.advance(source_id, GeoTaskPhase::Parsing);
        let summary = match child::build_snapshot(
            BuildRequest {
                input: &raw_path,
                output: &snapshot_path,
                source_id,
                kind: build_kind(&config.source),
            },
            cancel,
        )
        .await
        {
            Ok(summary) => summary,
            Err(GeoError::TaskCancelled) => {
                tracing::info!("refresh geo site source {} cancelled", config.name);
                return;
            }
            Err(e) => {
                tracing::error!("build geo site snapshot '{}' failed: {}", config.name, e);
                return;
            }
        };

        if cancel.is_cancelled() {
            return;
        }

        // Stage 3 - apply. The snapshot stays on disk as the rebuild source.
        self.tasks.advance(source_id, GeoTaskPhase::Applying);
        let apply_result =
            match self.apply_snapshot(&config.name, &snapshot_path, false, cancel).await {
                Ok(result) => result,
                Err(GeoError::TaskCancelled) => return,
                Err(e) => {
                    tracing::error!(
                        "apply geo site snapshot '{}' ({} entries) failed: {}",
                        config.name,
                        summary.entries,
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
            "apply geo site done: name={} entries={} changed_keys={} unchanged_keys={} deleted_keys={}",
            config.name,
            summary.entries,
            apply_result.changed_keys.len(),
            apply_result.unchanged_keys,
            apply_result.deleted_keys,
        );
        self.notify_geo_changes(apply_result.changed_keys).await;
    }

    /// Build the snapshot from the raw file when it is missing. Used by the
    /// restore path, which must not touch the network.
    async fn ensure_snapshot(
        &self,
        config: &GeoSiteSourceConfig,
        raw_path: &Path,
        snapshot_path: &Path,
        cancel: &CancellationToken,
    ) -> Result<bool, GeoError> {
        if snapshot_path.exists() {
            return Ok(true);
        }
        if !raw_path.exists() {
            return Ok(false);
        }
        if matches!(config.source, GeoSiteSource::Direct { .. }) {
            return Ok(false);
        }

        self.tasks.advance(config.id, GeoTaskPhase::Verifying);
        self.tasks.advance(config.id, GeoTaskPhase::Parsing);
        let summary = child::build_snapshot(
            BuildRequest {
                input: raw_path,
                output: snapshot_path,
                source_id: config.id,
                kind: build_kind(&config.source),
            },
            cancel,
        )
        .await?;
        tracing::info!(
            "built geo site snapshot for '{}' from raw ({} entries)",
            config.name,
            summary.entries
        );
        Ok(true)
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
            let Some(rule) = key_reader.next_prepared().map_err(|e| {
                GeoError::RawDatReadFailed(format!("read snapshot key {key} failed: {e}"))
            })?
            else {
                break;
            };
            batch.push(SiteRuleRow::from_prepared(
                rule.match_type,
                rule.value,
                rule.attributes_json,
                rule.pattern_valid,
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

fn build_kind(source: &GeoSiteSource) -> BuildKind {
    match source {
        GeoSiteSource::AdguardHome { key, .. } => BuildKind::SiteAdguard { key: key.clone() },
        _ => BuildKind::SiteDat,
    }
}
