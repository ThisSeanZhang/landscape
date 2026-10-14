pub(crate) mod answer;
pub(crate) mod cache;
pub(crate) mod chain;
pub(crate) mod engine;
pub(crate) mod local;
pub(crate) mod matcher;
pub(crate) mod redirect;
pub(crate) mod rule;

pub use local::{DohAdvertiseProvider, LocalDnsAnswerProvider};

use std::sync::Arc;

use crate::resolve::{cache::CacheHandle, engine::ResolveEngine, redirect::RedirectEngine};

/// Immutable, atomically swappable view of the DNS resolution state: the two
/// rule engines and the cache they share.
#[derive(Debug)]
pub(crate) struct RuntimeSnapshot {
    pub redirect_engine: Arc<RedirectEngine>,
    pub resolve_engine: Arc<ResolveEngine>,
    pub cache: CacheHandle,
}
