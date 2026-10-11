use std::{collections::HashMap, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use landscape_common::config_service::geo::{GeoSourceKind, GeoTaskPhase, GeoTaskProgress};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub mod ip_service;
pub mod raw_file;
pub mod site_service;

/// Minimum interval between two download-progress publishes for one task.
pub(crate) const GEO_PROGRESS_PUBLISH_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub(crate) struct GeoTaskEntry {
    cancel: CancellationToken,
    progress: GeoTaskProgress,
}

#[derive(Clone, Default)]
pub(crate) struct GeoTaskRegistry {
    entries: Arc<ArcSwap<HashMap<Uuid, GeoTaskEntry>>>,
}

impl GeoTaskRegistry {
    pub(crate) fn insert(
        &self,
        source_id: Uuid,
        kind: GeoSourceKind,
    ) -> Result<CancellationToken, ()> {
        let cancel = CancellationToken::new();
        let mut duplicate = false;
        self.entries.rcu(|current| {
            if current.contains_key(&source_id) {
                duplicate = true;
                return current.clone();
            }
            duplicate = false;
            let mut next = HashMap::clone(current);
            // TODO: every task starts in `Downloading`, so restore and upload
            // tasks report a wrong phase until their first `advance`.
            next.insert(
                source_id,
                GeoTaskEntry {
                    cancel: cancel.clone(),
                    progress: GeoTaskProgress::new(source_id, kind, GeoTaskPhase::Downloading),
                },
            );
            Arc::new(next)
        });
        if duplicate {
            return Err(());
        }
        Ok(cancel)
    }

    pub(crate) fn remove(&self, source_id: Uuid) {
        self.entries.rcu(|current| {
            if !current.contains_key(&source_id) {
                return current.clone();
            }
            let mut next = HashMap::clone(current);
            next.remove(&source_id);
            Arc::new(next)
        });
    }

    pub(crate) fn advance(&self, source_id: Uuid, phase: GeoTaskPhase) {
        self.entries.rcu(|current| {
            let Some(entry) = current.get(&source_id) else {
                return current.clone();
            };
            let mut next = HashMap::clone(current);
            let mut progress = entry.progress.clone();
            progress.advance(phase);
            next.insert(source_id, GeoTaskEntry { cancel: entry.cancel.clone(), progress });
            Arc::new(next)
        });
    }

    pub(crate) fn update_download(
        &self,
        source_id: Uuid,
        bytes_done: u64,
        bytes_total: Option<u64>,
    ) {
        self.entries.rcu(|current| {
            let Some(entry) = current.get(&source_id) else {
                return current.clone();
            };
            let mut next = HashMap::clone(current);
            let mut progress = entry.progress.clone();
            progress.set_download_progress(bytes_done, bytes_total);
            next.insert(source_id, GeoTaskEntry { cancel: entry.cancel.clone(), progress });
            Arc::new(next)
        });
    }

    pub(crate) fn cancel_task(&self, source_id: Uuid) -> bool {
        if let Some(entry) = self.entries.load().get(&source_id) {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub(crate) fn cancel_all(&self) {
        for entry in self.entries.load().values() {
            entry.cancel.cancel();
        }
    }

    pub(crate) fn progress_snapshot(&self) -> Vec<GeoTaskProgress> {
        self.entries.load().values().map(|entry| entry.progress.clone()).collect()
    }
}

pub(crate) enum GeoTaskMode {
    Download,
    RestoreOnly,
    Upload(Vec<u8>),
}

/// Removes the registry entry on drop, so a panicking task body cannot
/// leak its entry and permanently block the source with 409s.
pub(crate) struct TaskGuard(GeoTaskRegistry, Uuid);

impl TaskGuard {
    pub(crate) fn new(registry: GeoTaskRegistry, source_id: Uuid) -> Self {
        Self(registry, source_id)
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.remove(self.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_source_ids(registry: &GeoTaskRegistry) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = registry.progress_snapshot().iter().map(|p| p.source_id).collect();
        ids.sort();
        ids
    }

    #[test]
    fn insert_rejects_duplicate_until_removed() {
        let registry = GeoTaskRegistry::default();
        let id = Uuid::new_v4();

        assert!(registry.insert(id, GeoSourceKind::Ip).is_ok());
        assert!(registry.insert(id, GeoSourceKind::Ip).is_err());

        registry.remove(id);
        assert!(registry.insert(id, GeoSourceKind::Ip).is_ok());
        assert_eq!(snapshot_source_ids(&registry), vec![id]);
    }

    #[test]
    fn advance_updates_phase_and_download_progress() {
        let registry = GeoTaskRegistry::default();
        let id = Uuid::new_v4();
        registry.insert(id, GeoSourceKind::Site).unwrap();

        registry.update_download(id, 512, Some(2048));
        registry.advance(id, GeoTaskPhase::Parsing);

        let snapshot = registry.progress_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].phase, GeoTaskPhase::Parsing);
        assert_eq!(snapshot[0].bytes_done, 0);
        assert!(snapshot[0].bytes_total.is_none());
        assert!(snapshot[0].updated_at >= snapshot[0].started_at);
    }

    #[test]
    fn advance_and_update_ignore_unknown_source() {
        let registry = GeoTaskRegistry::default();
        registry.advance(Uuid::new_v4(), GeoTaskPhase::Applying);
        registry.update_download(Uuid::new_v4(), 1, Some(2));
        assert!(registry.progress_snapshot().is_empty());
        assert!(!registry.cancel_task(Uuid::new_v4()));
    }

    #[test]
    fn cancel_task_triggers_token_and_cancel_all_sweeps() {
        let registry = GeoTaskRegistry::default();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let first_cancel = registry.insert(first, GeoSourceKind::Ip).unwrap();
        let second_cancel = registry.insert(second, GeoSourceKind::Site).unwrap();

        assert!(registry.cancel_task(first));
        assert!(first_cancel.is_cancelled());
        assert!(!second_cancel.is_cancelled());

        registry.cancel_all();
        assert!(second_cancel.is_cancelled());
    }

    #[test]
    fn progress_timestamps_stay_in_millisecond_range() {
        let registry = GeoTaskRegistry::default();
        let id = Uuid::new_v4();
        registry.insert(id, GeoSourceKind::Ip).unwrap();
        registry.advance(id, GeoTaskPhase::Downloading);
        let snapshot = registry.progress_snapshot();
        assert!(snapshot[0].started_at > 1_000_000_000_000.0);
        assert!(snapshot[0].updated_at > 1_000_000_000_000.0);
    }

    #[test]
    fn task_guard_removes_entry_on_drop() {
        let registry = GeoTaskRegistry::default();
        let id = Uuid::new_v4();
        registry.insert(id, GeoSourceKind::Ip).unwrap();

        {
            let _guard = TaskGuard::new(registry.clone(), id);
            assert_eq!(snapshot_source_ids(&registry), vec![id]);
        }

        assert!(registry.progress_snapshot().is_empty());
        assert!(registry.insert(id, GeoSourceKind::Ip).is_ok());
    }

    #[test]
    fn task_guard_removes_entry_when_task_panics() {
        let registry = GeoTaskRegistry::default();
        let id = Uuid::new_v4();
        registry.insert(id, GeoSourceKind::Site).unwrap();

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = TaskGuard::new(registry.clone(), id);
            panic!("simulated task panic");
        }));
        assert!(panicked.is_err());

        assert!(registry.progress_snapshot().is_empty());
        assert!(registry.insert(id, GeoSourceKind::Site).is_ok());
    }
}
