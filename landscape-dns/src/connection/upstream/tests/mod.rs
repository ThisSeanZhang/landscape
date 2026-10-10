//! Unit tests for the upstream pool, split by area:
//! - [`conn`]: connection acquisition, reuse, racing, warm-up, maintenance
//! - [`fanout`]: concurrent fan-out response selection
//! - [`health`]: upstream offline / probe behaviour
//! - [`lookup`]: retry loop, budgets, truncation fallback
//! - [`cname`]: CNAME chain following
//! - [`capacity`]: DoH / DoQ saturation surfaces the capacity error class
//! - [`tls_pool`]: DoT / DoH / DoQ end-to-end against a local hickory-server
//! - [`quic_keepalive`]: DoQ keep-alive / idle-timeout / stream multiplexing
//! - [`quic_connector`]: native quinn DoQ connector against a minimal echo peer
//! - [`scripted`]: real-transport failure modes against a scripted plaintext
//!   peer (RST, spoofing, blackhole, restart, flapping)
//!
//! Real-transport coverage also lives in [`crate::connection::integration_tests`]
//! (end-to-end plaintext lookups). The shared TLS/QUIC harness (certificates,
//! hickory-server spawner, quinn echo server) lives in [`tls_support`].
//!
//! NOTE: these suites dial through `MarkRuntimeProvider`, which sets SO_MARK
//! on every socket — they require CAP_NET_ADMIN (run as root, or via the
//! `rust-privileged-tests` CI job). Without the capability the dials fail
//! with EPERM and the affected tests error out instead of skipping.

use std::net::Ipv4Addr;

use super::*;
use crate::connection::upstream::mocks::*;
use crate::connection::upstream::pool_config::PoolConfig;
use crate::connection::upstream::traits::{DnsConnError, DnsTransport};
use hickory_proto::rr::rdata::A;
use landscape_common::dns::upstream::DnsUpstreamMode;

pub(super) mod capacity;
pub(super) mod cname;
pub(super) mod conn;
pub(super) mod fanout;
pub(super) mod health;
pub(super) mod lookup;
pub(super) mod quic_connector;
pub(super) mod quic_keepalive;
pub(super) mod scripted;
pub(super) mod tls_pool;
pub(super) mod tls_support;

/// A single-connector stream pool with the given attempt budget.
pub(super) fn stream_pool(connector: Arc<MockConnector>, attempts: u8) -> Arc<UpstreamPool> {
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = attempts;
    UpstreamPool::with_connectors(vec![connector], config)
}

/// Like [`stream_pool`], but with a near-zero `stale_conn_age` so that
/// [`age_all`] reliably makes connections stale even right after process
/// start (the clock is process-relative, so a default 30s threshold would
/// never be met by a fresh process).
pub(super) fn race_pool(connector: Arc<MockConnector>, attempts: u8) -> Arc<UpstreamPool> {
    let mut config = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
    config.attempts = attempts;
    config.stale_conn_age = Duration::from_millis(1);
    UpstreamPool::with_connectors(vec![connector], config)
}

/// Ages every pooled connection beyond `stale_conn_age` so the next query
/// races it against a fresh dial. Both activity stamps are aged: the
/// completion stamp (stale/LRU logic) and the borrow stamp (idle reaping).
pub(super) fn age_all(pool: &UpstreamPool) {
    let conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
    for pooled in conns.iter() {
        pooled.last_used_ms.store(0, Ordering::Relaxed);
        pooled.last_borrow_ms.store(0, Ordering::Relaxed);
    }
}

/// A manually-advanceable clock for deterministic time-sensitive tests
/// (probe intervals, stale age, idle reaping) via
/// [`UpstreamPool::with_connectors_and_clock`]. Clones share the counter,
/// so the test handle and the pool's `Arc` see the same time.
#[derive(Debug, Default)]
pub(super) struct TestClock {
    now: Arc<std::sync::atomic::AtomicU64>,
}

impl Clone for TestClock {
    fn clone(&self) -> Self {
        Self { now: self.now.clone() }
    }
}

impl TestClock {
    pub(super) fn new(start_ms: u64) -> Self {
        Self {
            now: Arc::new(std::sync::atomic::AtomicU64::new(start_ms)),
        }
    }

    pub(super) fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now.load(std::sync::atomic::Ordering::Relaxed).max(1)
    }
}
