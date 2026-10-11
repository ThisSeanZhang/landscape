use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use landscape_common::ddns::{DdnsTaskPhase, DdnsTaskProgress};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone)]
struct DdnsTaskEntry {
    cancel: CancellationToken,
    progress: DdnsTaskProgress,
    /// Reconcile-loop dirty flag: set by triggers arriving while this task runs.
    pending: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
pub(super) struct DdnsTaskRegistry {
    entries: Arc<ArcSwap<HashMap<Uuid, DdnsTaskEntry>>>,
}

pub(super) enum DdnsTaskStart {
    Started(CancellationToken),
    MarkedPending,
}

pub(super) enum DdnsTaskFinish {
    /// The pending flag was set: keep the entry and run another round.
    Continue,
    /// No pending work: the entry was removed.
    Stopped,
}

impl DdnsTaskRegistry {
    /// Strict insert for user-initiated sync: fails when a task already runs.
    pub(super) fn insert(&self, id: Uuid) -> Result<CancellationToken, ()> {
        let cancel = CancellationToken::new();
        let mut duplicate = false;
        self.entries.rcu(|current| {
            if current.contains_key(&id) {
                duplicate = true;
                return current.clone();
            }
            duplicate = false;
            let mut next = HashMap::clone(current);
            next.insert(
                id,
                DdnsTaskEntry {
                    cancel: cancel.clone(),
                    progress: DdnsTaskProgress::new(id),
                    pending: Arc::new(AtomicBool::new(false)),
                },
            );
            Arc::new(next)
        });
        if duplicate { Err(()) } else { Ok(cancel) }
    }

    /// Start when the slot is free, else mark the running task's pending flag.
    pub(super) fn start_or_mark(&self, id: Uuid) -> DdnsTaskStart {
        let mut started = None;
        self.entries.rcu(|current| {
            // rcu retries under contention: drop any token from a lost
            // attempt so we never report an orphaned start.
            started = None;
            if let Some(entry) = current.get(&id) {
                entry.pending.store(true, Ordering::Release);
                return current.clone();
            }
            let cancel = CancellationToken::new();
            let mut next = HashMap::clone(current);
            next.insert(
                id,
                DdnsTaskEntry {
                    cancel: cancel.clone(),
                    progress: DdnsTaskProgress::new(id),
                    pending: Arc::new(AtomicBool::new(false)),
                },
            );
            started = Some(cancel);
            Arc::new(next)
        });
        match started {
            Some(cancel) => DdnsTaskStart::Started(cancel),
            None => DdnsTaskStart::MarkedPending,
        }
    }

    /// Consume a pending mark (keep the entry, reset progress) or remove the
    /// entry; one rcu so a racing mark is never discarded with the entry.
    pub(super) fn finish_or_continue(&self, id: Uuid) -> DdnsTaskFinish {
        let mut keep_going = false;
        self.entries.rcu(|current| {
            let Some(entry) = current.get(&id) else {
                keep_going = false;
                return current.clone();
            };
            let mut next = HashMap::clone(current);
            // The pending flag lives on a shared Arc, so a failed rcu attempt
            // may already have consumed a mark; honor it across retries.
            keep_going = entry.pending.swap(false, Ordering::AcqRel) || keep_going;
            if keep_going {
                next.insert(
                    id,
                    DdnsTaskEntry {
                        cancel: entry.cancel.clone(),
                        progress: DdnsTaskProgress::new(id),
                        pending: entry.pending.clone(),
                    },
                );
            } else {
                keep_going = false;
                next.remove(&id);
            }
            Arc::new(next)
        });
        if keep_going { DdnsTaskFinish::Continue } else { DdnsTaskFinish::Stopped }
    }

    pub(super) fn has_task(&self, id: Uuid) -> bool {
        self.entries.load().contains_key(&id)
    }

    pub(super) fn remove(&self, id: Uuid) {
        self.entries.rcu(|current| {
            if !current.contains_key(&id) {
                return current.clone();
            }
            let mut next = HashMap::clone(current);
            next.remove(&id);
            Arc::new(next)
        });
    }

    pub(super) fn update_phase(&self, id: Uuid, phase: DdnsTaskPhase, detail: Option<String>) {
        self.entries.rcu(|current| {
            let Some(entry) = current.get(&id) else {
                return current.clone();
            };
            let mut next = HashMap::clone(current);
            let mut progress = entry.progress.clone();
            progress.advance(phase, detail.clone());
            next.insert(
                id,
                DdnsTaskEntry {
                    cancel: entry.cancel.clone(),
                    progress,
                    pending: entry.pending.clone(),
                },
            );
            Arc::new(next)
        });
    }

    pub(super) fn cancel_task(&self, id: Uuid) -> bool {
        if let Some(entry) = self.entries.load().get(&id) {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub(super) fn cancel_all(&self) {
        for entry in self.entries.load().values() {
            entry.cancel.cancel();
        }
    }

    pub(super) fn progress_snapshot(&self) -> Vec<DdnsTaskProgress> {
        self.entries.load().values().map(|entry| entry.progress.clone()).collect()
    }
}
