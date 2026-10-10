//! Upstream connection pool.
//!
//! One [`UpstreamPool`] per `(dns_mark, upstream_id)` replaces the old
//! hickory `Resolver` instance. It owns:
//!
//! - a set of connectors (one per upstream IP × protocol, built by
//!   [`native::build_connectors`]),
//! - the established connections (with warm-up, caps, idle reaping),
//! - the query execution (attempts, UDP→stream fallback, error taxonomy),
//! - upstream health (consecutive failures → offline, fast-fail + revival).
//!
//! All protocol details live behind the [`traits::DnsConnector`] boundary
//! (implemented by the [`native`] transports), so the transport stack can
//! be swapped without touching this module.
//!
//! # Design rules (single source of truth)
//!
//! - **Revival criterion**: an upstream is alive when it answers — success
//!   or an explicit protocol code (`NXDomain`, `ServFail`, ...) — and is
//!   considered dead only after consecutive *transport-level* failures
//!   (`Timeout`, I/O). `NoConnections` — the transports' capacity signal,
//!   surfaced by every stream transport's in-flight cap — is a capacity
//!   condition and never counts. Permanent TLS failures (`Tls`,
//!   e.g. a bad certificate) are config-level, never count, and fail fast
//!   instead of retrying. In-band lookups and the maintenance probe apply
//!   the same criterion.
//! - **Error selection**: when every fan-out leg (or every attempt) fails,
//!   the most informative error wins, independent of leg completion order:
//!   explicit protocol codes first (the server answered, and the code is
//!   final), then connectivity-class errors (`Timeout`/`Internal`/`Tls`),
//!   then the capacity-class `NoConnections`.
//! - **Truncated answers** are a fallback for transport-level retry
//!   failures only: an explicit negative (or error code) from the stream
//!   retry outranks the partial UDP answer. A truncated answer with no data
//!   is never surfaced as an empty success — the caller would cache it as a
//!   negative for a domain that demonstrably exists. A partial (non-empty)
//!   truncated answer surfaces with the `LookupAnswer::truncated` flag: the
//!   caller serves it with the TC bit and never caches it as complete.
//! - **Explicit codes are final**: `NXDomain`/`NoError` are negative
//!   answers (with the authority-section SOA preserved for RFC 2308
//!   negative caching), `ServFail`/`Refused`/... are returned after one
//!   attempt (matching the old hickory RetryDnsHandle, which never retried
//!   response-code errors); only transport failures are retried. Permanent
//!   TLS failures are final too.
//! - **`max_conns` is a per-upstream budget** across all endpoints (UDP
//!   sockets are exempt); `min_conns` is a per-pool warm floor, effectively
//!   capped at the stream endpoint count.
//! - **Offline probing**: while offline every client query fast-fails;
//!   revival is driven by a spawned probe loop (one probe at a time, one
//!   every `probe_interval`), so a dropped client query can never strand
//!   the health state.
//!
//! The old hickory-resolver answered from `/etc/hosts` (`use_hosts_file` was
//! commented out, so the `Auto` default applied); the pool deliberately does
//! not — `stage_local` already intercepts local names before the upstream
//! stage, matching the intent of the commented-out setting.

use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{DnsRequestOptions, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rand::RngExt;
use tokio::task::JoinSet;
use uuid::Uuid;

use landscape_common::dns::config::DnsUpstreamConfig;

use crate::connection::upstream::pool_config::{PoolConfig, PoolSettings};
use crate::connection::upstream::traits::{DnsConn, DnsConnector, DnsTransport};

pub(crate) mod native;
pub(crate) mod pool_config;
pub(crate) mod traits;

/// Scripted mock connectors shared by the `upstream` and `rule` test suites.
#[cfg(test)]
pub(crate) mod mocks;

/// Errors a whole upstream lookup can fail with; mapped to
/// `DnsServiceError` by the caller (`rule.rs`).
#[derive(Debug)]
pub(crate) enum UpstreamError {
    /// Every attempt exhausted the query budget.
    Timeout,
    /// Upstream answered an explicit code (NXDomain/NoError-empty included,
    /// so the caller can map them to negative answers). When the answer was
    /// a negative one, the authority-section SOA rides along so the caller
    /// can honour RFC 2308 negative caching.
    Protocol(ResponseCode, Option<Box<Record>>),
    /// No connector or connection was usable (pool cap reached, no usable
    /// connectors). A capacity condition, not a connectivity failure: it
    /// says nothing about upstream reachability.
    NoConnections,
    /// The upstream is marked offline and this query was refused before the
    /// probe interval expired (fast-fail). The caller should treat it like
    /// a timeout: the upstream is unreachable right now.
    Offline,
    /// A permanent TLS failure (certificate verification, handshake policy):
    /// retrying cannot succeed, so it fails fast and never counts towards
    /// the offline flip or connection retirement.
    Tls(String),
    /// Unexpected internal failure.
    Internal(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Timeout => write!(f, "upstream lookup timed out"),
            UpstreamError::Protocol(code, _) => write!(f, "upstream answered {code}"),
            UpstreamError::NoConnections => write!(f, "no usable upstream connections"),
            UpstreamError::Offline => write!(f, "upstream is offline (fast-fail)"),
            UpstreamError::Tls(e) => write!(f, "upstream TLS failure: {e}"),
            UpstreamError::Internal(e) => write!(f, "upstream internal error: {e}"),
        }
    }
}

/// Outcome of one concurrent fan-out attempt.
enum FanOutVerdict {
    /// A usable answer (positive, or truncated when stream legs already ran).
    Answer(Message),
    /// An explicit negative answer (NXDomain/NoData) is final; the SOA
    /// record (when the upstream sent one) rides along so the caller can
    /// honour RFC 2308 negative caching.
    Negative(ResponseCode, Option<Box<Record>>),
    /// A truncated UDP answer arrived and no positive answer did. Preferred
    /// over a negative: truncation means the data exists (it just does not
    /// fit over UDP), so the caller retries stream-only and may recover it,
    /// whereas the negative from another endpoint would be premature.
    Truncated(Message),
    /// Every leg failed with a transient error.
    Failed(UpstreamError),
}

/// A message with no answers and an explicit negative code.
///
/// Defensive: the real hickory path already converts every empty
/// NoError/NXDomain response into `Err(Protocol(..))` inside
/// `classify_response`, so `fan_out` never sees one as `Ok(..)`. The check
/// is kept so a future native transport (or the mock connectors) that
/// surfaces negatives as messages still gets the balanced selection.
fn is_negative_response(message: &Message) -> bool {
    message.answers.is_empty()
        && matches!(message.metadata.response_code, ResponseCode::NoError | ResponseCode::NXDomain)
}

/// The SOA record of a message's authority section, if any (RFC 2308
/// negative caching). Boxed to keep the error types small on the hot path.
fn soa_of_message(message: &Message) -> Option<Box<Record>> {
    message
        .authorities
        .iter()
        .find(|record| matches!(record.data, RData::SOA(_)))
        .cloned()
        .map(Box::new)
}

/// Relative informativeness of a failed leg's error: lower rank wins when
/// every leg fails. An explicit protocol code proves the server answered
/// (and is final), connectivity-class errors (`Timeout`/`Internal`) describe
/// real reachability problems, a permanent TLS failure is also
/// connectivity-class (but final), and the capacity-class `NoConnections`
/// says nothing about upstream reachability.
fn error_rank(e: &UpstreamError) -> u8 {
    match e {
        UpstreamError::Protocol(_, _) => 0,
        UpstreamError::Timeout | UpstreamError::Internal(_) | UpstreamError::Tls(_) => 1,
        UpstreamError::NoConnections => 2,
        // Legs never produce `Offline`; kept so the rank is total.
        UpstreamError::Offline => 3,
    }
}

/// Keeps the more informative error (`error_rank`) between `best` and
/// `incoming`, so the reported failure does not depend on leg completion
/// order (a capacity error arriving last must not mask a connectivity one).
fn select_better_error(best: &mut Option<UpstreamError>, incoming: UpstreamError) {
    if best.as_ref().map(error_rank).unwrap_or(u8::MAX) > error_rank(&incoming) {
        *best = Some(incoming);
    }
}

/// Rotates `legs` from a random start and truncates to `cap`, spreading the
/// fan-out across all endpoints across attempts.
fn rotate_capped(legs: &[usize], cap: usize) -> Vec<usize> {
    if legs.is_empty() || cap == 0 {
        return Vec::new();
    }
    let n = legs.len().min(cap);
    let start = rand::rng().random_range(0..legs.len());
    (0..n).map(|i| legs[(start + i) % legs.len()]).collect()
}

/// Per-connection runtime state kept by the pool.
#[derive(Debug)]
struct PooledConn {
    conn: Arc<dyn DnsConn>,
    /// Millis since the process start (monotonic-ish clock) of last
    /// *completed* use: LRU order, staleness racing, and idle reaping all
    /// read this.
    last_used_ms: AtomicU64,
    /// Millis of the last *borrow* (a query started on this connection,
    /// completion pending). The idle reaper considers both stamps: a query
    /// in flight on an almost-idle connection must not let the maintenance
    /// pass reap — and for DoQ, actively close — the connection under the
    /// query. Kept separate from `last_used_ms` so a borrow never makes a
    /// just-failed connection look freshly *successful* to the LRU/stale
    /// logic.
    last_borrow_ms: AtomicU64,
    consecutive_failures: AtomicU32,
    /// Set when the connection must be replaced (closed on reap).
    dead: AtomicBool,
    /// Whether the connection was inserted into the pool's `conns` vector.
    /// Until it is, the `PooledConn` Arc is the only reference (e.g. a
    /// cap-excess use-then-drop connection): the `Drop` impl closes the
    /// connection then, so every dialed connection honours the shutdown
    /// contract — explicitly via the retirement paths once pooled, via
    /// `Drop` before.
    pooled: AtomicBool,
}

impl PooledConn {
    fn new(conn: Arc<dyn DnsConn>, now_ms: u64) -> Self {
        Self {
            conn,
            last_used_ms: AtomicU64::new(now_ms),
            last_borrow_ms: AtomicU64::new(now_ms),
            consecutive_failures: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            pooled: AtomicBool::new(false),
        }
    }

    /// Millis since the process start when the connection was last free of
    /// an in-flight query — the later of the completion and borrow stamps.
    /// The idle reaper's activity measure.
    fn last_active_ms(&self) -> u64 {
        self.last_used_ms.load(Ordering::Relaxed).max(self.last_borrow_ms.load(Ordering::Relaxed))
    }

    /// Marks the connection as pooled (caller must hold the `conns` lock);
    /// from then on the retirement paths own the shutdown.
    fn mark_pooled(&self) {
        self.pooled.store(true, Ordering::Relaxed);
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        // A connection that never made it into the pool (cap-excess
        // use-then-drop, or a raced fresh conn that lost the insertion
        // race) has no retirement path to close it: close it here so the
        // shutdown contract holds for every dialed connection.
        if !self.pooled.load(Ordering::Relaxed) {
            self.conn.shutdown();
        }
    }
}

/// Upstream health state: flips offline after repeated lookup failures and
/// fast-fails new queries until the pool's revival probe loop succeeds.
///
/// Revival probes run exclusively on a spawned task loop (see
/// [`UpstreamPool::spawn_revival_probes`]) that is never cancelled
/// mid-probe, so no claim/stale-recovery bookkeeping is needed: a client
/// query can be dropped at any moment without stranding the health state.
#[derive(Debug)]
struct Health {
    offline: AtomicBool,
    consecutive_failures: AtomicU32,
}

impl Health {
    fn new() -> Self {
        Self {
            offline: AtomicBool::new(false),
            consecutive_failures: AtomicU32::new(0),
        }
    }

    /// Records one connectivity failure; returns whether this failure
    /// flipped the upstream offline (the caller spawns the revival probe
    /// loop at that point).
    fn record_failure(&self) -> bool {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= pool_config::UPSTREAM_FAILURE_THRESHOLD
            && self
                .offline
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!("upstream marked offline after {failures} consecutive failures");
            return true;
        }
        false
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if self.offline.compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            tracing::info!("upstream revived");
        }
    }

    /// Whether a new query may attempt the upstream right now. While
    /// offline every query fast-fails; probing is the revival loop's job.
    fn admit(&self) -> bool {
        !self.offline.load(Ordering::Relaxed)
    }
}

/// Process-relative millisecond clock for idle/failure/probe bookkeeping.
/// Injected into the pool so tests can control time deterministically; the
/// production [`MonotonicClock`] is monotonic so wall-clock jumps (NTP
/// steps) cannot corrupt idle reaping or probe timing.
pub(crate) trait Clock: Send + Sync + std::fmt::Debug {
    /// Current time in process-relative milliseconds.
    fn now_ms(&self) -> u64;
}

/// The production clock. Never returns 0: the probe gate treats 0 as the
/// "never probed" sentinel, so a real claim must be distinguishable from it.
#[derive(Debug)]
pub(crate) struct MonotonicClock;

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_millis().max(1) as u64
    }
}

/// Result of an upstream lookup: the answer records plus whether they are a
/// partial (truncated) answer. A truncated answer must not be cached as a
/// complete answer and must reach the client with the TC bit set so the
/// client retries over TCP.
#[derive(Debug, Clone)]
pub struct LookupAnswer {
    pub records: Vec<Record>,
    pub truncated: bool,
}

impl std::ops::Deref for LookupAnswer {
    type Target = Vec<Record>;

    fn deref(&self) -> &Vec<Record> {
        &self.records
    }
}

impl IntoIterator for LookupAnswer {
    type Item = Record;
    type IntoIter = std::vec::IntoIter<Record>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter()
    }
}

/// Decrements the slot's background-dial count when dropped, so a panicked
/// or early-returning dial task can never leave the counter stuck above
/// zero (which would silently disable elastic growth forever).
struct DialGuard<'a>(&'a AtomicUsize);

impl Drop for DialGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Per-endpoint dial state. Keeping the background (scale-up) dial count per
/// endpoint — not per pool — means a scale-up dial in flight for one IP can
/// never suppress elastic growth for another IP of the same upstream.
#[derive(Debug, Default)]
struct DialSlot {
    /// Cold-dial single-flight: a burst of concurrent lookups on a cold
    /// pool takes turns dialing and reuses the pooled result, instead of
    /// hammering the peer with parallel handshakes — a peer that
    /// rate-limits handshakes would surface the duplicates as
    /// health-counted `Io` failures (3 flip the upstream offline from
    /// cold-start pressure alone).
    gate: tokio::sync::Mutex<()>,
    /// Background (scale-up) dial in flight (0 or 1).
    background_dial: AtomicUsize,
}

/// Point-in-time pool state for diagnostics (see
/// [`UpstreamPool::snapshot`]). Fields are consumed via `Debug` (the
/// maintenance pass logs the snapshot) and by future observers; dead-code
/// analysis cannot see Debug-only reads.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct UpstreamSnapshot {
    pub(crate) upstream_id: Uuid,
    pub(crate) flow_id: u32,
    pub(crate) dns_mark: u32,
    /// Whether the upstream is currently blacklisted (queries fast-fail
    /// until the revival probe loop succeeds).
    pub(crate) offline: bool,
    /// Current consecutive connectivity-failure streak.
    pub(crate) consecutive_failures: u32,
    /// Pooled connections across all transports.
    pub(crate) conns_total: usize,
    /// Pooled stream (TCP/TLS/DoH/DoQ) connections.
    pub(crate) conns_stream: usize,
    /// Pooled UDP bookkeeping entries (stateless sockets; per-query dials).
    pub(crate) conns_udp: usize,
    /// Background (scale-up) dials in flight across all endpoints.
    pub(crate) background_dials: usize,
}

/// The connection pool for one (mark, upstream) pair.
#[derive(Debug)]
pub(crate) struct UpstreamPool {
    flow_id: u32,
    dns_mark: u32,
    upstream_id: Uuid,
    config: PoolConfig,
    connectors: Vec<Arc<dyn DnsConnector>>,
    conns: Mutex<Vec<Arc<PooledConn>>>,
    health: Health,
    /// Per-endpoint dial state (cold-dial single-flight gate + background
    /// scale-up dial slot), keyed by `(ip, transport)`. The map is bounded
    /// by the connector set's size and lives with the pool.
    dial_slots: Mutex<std::collections::HashMap<(IpAddr, DnsTransport), Arc<DialSlot>>>,
    /// Time source for idle/stale bookkeeping.
    clock: Arc<dyn Clock>,
}

impl UpstreamPool {
    /// Builds the pool and its connectors. Returns `None` when no connector
    /// could be constructed (e.g. TLS config failure), in which case the
    /// caller skips the rule — matching the old `create_resolver` behaviour.
    ///
    /// `settings` currently comes from `PoolSettings::default()`; when
    /// per-upstream tuning is exposed later, only the call site needs to
    /// change.
    ///
    /// `tls_config` is an injection point: production passes `None` (platform
    /// verifier); tests pass a prepared config that trusts a test CA.
    pub(crate) fn new(
        flow_id: u32,
        dns_mark: u32,
        upstream: &DnsUpstreamConfig,
        provider: crate::connection::provider::MarkRuntimeProvider,
        settings: &PoolSettings,
        tls_config: Option<Arc<rustls::ClientConfig>>,
    ) -> Option<Arc<Self>> {
        let config = PoolConfig::from_settings(&upstream.mode, settings);
        let connectors = native::build_connectors(
            &upstream.mode,
            &upstream.ips,
            upstream.port,
            provider,
            &config,
            tls_config,
        );
        if connectors.is_empty() {
            tracing::error!(
                "[flow: {flow_id}]: failed to build upstream connectors for {}",
                upstream.id
            );
            return None;
        }

        let clock: Arc<dyn Clock> = Arc::new(MonotonicClock);
        let pool = Arc::new(Self {
            flow_id,
            dns_mark,
            upstream_id: upstream.id,
            config,
            connectors,
            conns: Mutex::new(vec![]),
            health: Health::new(),
            dial_slots: Mutex::new(std::collections::HashMap::new()),
            clock,
        });
        pool.spawn_maintenance();
        pool.spawn_warmup();
        Some(pool)
    }

    /// Test-only constructor: builds a pool around pre-made connectors (no
    /// real network I/O), so pool behaviour can be verified with mocks.
    /// Deliberately does not spawn the build-time warm-up so tests control
    /// dialing exactly (warm-up is exercised via `warm_up_to_min`).
    #[cfg(test)]
    pub(crate) fn with_connectors(
        connectors: Vec<Arc<dyn DnsConnector>>,
        config: PoolConfig,
    ) -> Arc<Self> {
        Self::with_connectors_and_clock(connectors, config, Arc::new(MonotonicClock))
    }

    /// Test-only constructor with an injectable clock, for deterministic
    /// time-sensitive tests (probe intervals, stale age, idle reaping).
    #[cfg(test)]
    pub(crate) fn with_connectors_and_clock(
        connectors: Vec<Arc<dyn DnsConnector>>,
        config: PoolConfig,
        clock: Arc<dyn Clock>,
    ) -> Arc<Self> {
        let pool = Arc::new(Self {
            flow_id: 7,
            dns_mark: 0x8000,
            upstream_id: Uuid::new_v4(),
            config,
            connectors,
            conns: Mutex::new(vec![]),
            health: Health::new(),
            dial_slots: Mutex::new(std::collections::HashMap::new()),
            clock,
        });
        pool.spawn_maintenance();
        pool
    }

    /// Current number of pooled connections (any transport). Test-facing
    /// introspection; not part of the public API contract.
    #[cfg(test)]
    pub(crate) fn conn_count(&self) -> usize {
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Point-in-time diagnostics snapshot: health, connection and dial
    /// state in one consistent read. Intended for logging (the maintenance
    /// pass emits it at debug level) and for operators answering "why is
    /// this upstream blacklisted / slow" without adding atomics to hot
    /// paths.
    pub(crate) fn snapshot(&self) -> UpstreamSnapshot {
        let (conns_total, conns_stream) = {
            let conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
            let total = conns.len();
            let stream =
                conns.iter().filter(|p| p.conn.transport() == DnsTransport::Stream).count();
            (total, stream)
        };
        let background_dials: usize = {
            let slots = self.dial_slots.lock().unwrap_or_else(|e| e.into_inner());
            slots.values().map(|slot| slot.background_dial.load(Ordering::Relaxed)).sum()
        };
        UpstreamSnapshot {
            upstream_id: self.upstream_id,
            flow_id: self.flow_id,
            dns_mark: self.dns_mark,
            offline: self.health.offline.load(Ordering::Relaxed),
            consecutive_failures: self.health.consecutive_failures.load(Ordering::Relaxed),
            conns_total,
            conns_stream,
            conns_udp: conns_total - conns_stream,
            background_dials,
        }
    }

    /// Resolves `domain` for `query_type`, mirroring the old resolver
    /// semantics: `attempts` tries, each bounded by `query_timeout`, with
    /// UDP→stream fallback on truncation, a lookup-level deadline
    /// (`attempts × query_timeout + connect_timeout`), and fast-fail while
    /// offline.
    pub(crate) async fn lookup(
        self: &Arc<Self>,
        domain: &str,
        query_type: RecordType,
    ) -> Result<LookupAnswer, UpstreamError> {
        let name = match Name::from_str(domain) {
            Ok(name) => name,
            Err(e) => return Err(UpstreamError::Internal(format!("invalid domain: {e}"))),
        };
        let query = Query::query(name, query_type);
        let options = request_options();

        // While offline every query fast-fails instead of burning the full
        // attempts budget on a dead upstream; probing for revival is the
        // spawned probe loop's job (see [`UpstreamPool::spawn_revival_probes`]),
        // so a client query being dropped can never strand the health
        // state. The fast-fail is surfaced as `Offline` (a distinct error
        // from the capacity-bound `NoConnections`) so the caller can map it
        // to a client timeout.
        if !self.health.admit() {
            return Err(UpstreamError::Offline);
        }

        let result = self.lookup_with_attempts(&query, &options, self.config.attempts).await;
        match &result {
            Ok(_) => self.health.record_success(),
            // Explicit upstream answers (NXDomain, ServFail, ...) are not
            // connectivity failures: the upstream is alive and answering.
            Err(UpstreamError::Protocol(_, _)) => self.health.record_success(),
            // Capacity-induced NoConnections (pool cap reached, no usable
            // connectors) says nothing about upstream reachability: it
            // neither counts towards the offline flip nor resets the failure
            // streak. The same holds for the offline fast-fail.
            Err(UpstreamError::NoConnections | UpstreamError::Offline) => {}
            // Permanent TLS failures (bad certificate, ...) never count
            // towards the offline flip either: retrying or probing cannot
            // fix them.
            Err(UpstreamError::Tls(_)) => {}
            // Transient connectivity failures count towards the offline
            // flip; the flip spawns the revival probe loop.
            Err(UpstreamError::Timeout | UpstreamError::Internal(_)) => {
                if self.health.record_failure() {
                    self.spawn_revival_probes();
                }
            }
        }
        result
    }

    /// Runs the retry loop for one query and returns the winning message. On
    /// UDP truncation it switches to stream-only connectors for the remaining
    /// attempts (old `try_tcp_on_error` path).
    ///
    /// The whole lookup is bounded by `deadline` (computed once by
    /// `lookup_with_attempts` as `attempts × query_timeout + connect_timeout`
    /// and shared across every CNAME hop, so a chase cannot re-arm the budget
    /// per hop), so slow dials in later attempts — or a truncation that
    /// forces a second cold connect — cannot stretch the lookup without
    /// limit; each attempt still gets its own connect budget and existing
    /// connections are always preferred. The caller's outer timeout remains
    /// the final bound for the client.
    async fn lookup_message(
        self: &Arc<Self>,
        query: &Query,
        options: &DnsRequestOptions,
        attempts: u8,
        deadline: tokio::time::Instant,
    ) -> Result<Message, UpstreamError> {
        let mut force_stream = false;
        let mut last_err: Option<UpstreamError> = None;
        // A truncated UDP answer whose stream retry never got to run is
        // returned at the end if it carries data (it just did not fit over
        // UDP, so surfacing it beats a fabricated internal error). An *empty*
        // truncated answer is never returned: it would surface as an empty
        // NOERROR and be cached as a negative for a domain that demonstrably
        // exists — the transport error it degenerated to is more honest.
        let mut truncated: Option<Message> = None;

        for _ in 0..attempts {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Every attempt may dial missing connections: a cold handshake
            // gets its own (larger) connect budget, and the lookup-level
            // deadline above keeps the total bounded. A mid-attempt expiry
            // falls through to the truncated guard below instead of
            // returning directly: a stored non-empty partial answer beats
            // the timeout error.
            let outcome =
                match tokio::time::timeout(remaining, self.attempt(query, options, force_stream))
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        select_better_error(&mut last_err, UpstreamError::Timeout);
                        break;
                    }
                };
            match outcome {
                Ok(message) => {
                    // Truncated answer: switch to stream-only connectors for
                    // the remaining attempts (old `try_tcp_on_error` path).
                    // A truncation that recurs while already in stream mode
                    // (`force_stream`) is returned as-is when it carries
                    // answers — there is no other transport to recover it,
                    // so the partial answer surfaces — but an empty one is
                    // turned into the most informative transport error.
                    if message.metadata.truncation && !force_stream {
                        force_stream = true;
                        truncated = Some(message);
                        continue;
                    }
                    if message.metadata.truncation && message.answers.is_empty() {
                        // An empty truncated answer in stream mode is never
                        // a success — but it must not discard the non-empty
                        // UDP partial stored in `truncated` either (that
                        // would break the module invariant "a stored partial
                        // beats the error it degenerated to"). Fall through
                        // to the post-loop handling, which runs the same
                        // decision and returns the partial.
                        break;
                    }
                    return Ok(message);
                }
                Err(e) => {
                    // Explicit protocol answers are final: the server is
                    // alive and answered (matching the old hickory
                    // RetryDnsHandle, which never retried response-code
                    // errors). NXDomain/NoError-empty are the negative
                    // cases; ServFail/Refused and friends would only be
                    // repeated deterministically by another attempt, so
                    // retrying would amplify load and latency on an
                    // erroring upstream. Permanent TLS failures are final
                    // too: a bad certificate cannot be fixed by retrying.
                    // Endpoint diversity within one attempt is still
                    // provided by the fan-out; only transport failures —
                    // timeouts, connection errors, internal errors — are
                    // transient and retried.
                    if matches!(e, UpstreamError::Protocol(_, _) | UpstreamError::Tls(_)) {
                        return Err(e);
                    }
                    select_better_error(&mut last_err, e);
                }
            }
        }

        // A truncation that consumed the final attempt still gets one
        // stream-only attempt under whatever remains of the deadline: the
        // pool retries TCP itself rather than handing the client a partial
        // answer. When that attempt fails at the transport level (or the
        // deadline is already spent) the truncated answer is returned
        // instead of an error — unless it is empty, in which case the
        // transport error it degenerated to is returned (see above); an
        // explicit protocol answer from the stream retry (NXDomain,
        // ServFail, ...) is more authoritative than the partial UDP answer
        // and wins.
        if let Some(message) = truncated {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if !remaining.is_zero() {
                match tokio::time::timeout(remaining, self.attempt(query, options, true)).await {
                    Ok(Ok(answer)) => {
                        // Same invariant as the in-loop handling: an empty
                        // truncated answer is never returned as success —
                        // it would surface (and cache) as an empty NOERROR.
                        // The non-empty partial from the UDP leg (if any)
                        // still wins over the error.
                        if answer.metadata.truncation && answer.answers.is_empty() {
                            if !message.answers.is_empty() {
                                return Ok(message);
                            }
                            return Err(last_err.take().unwrap_or(UpstreamError::Timeout));
                        }
                        return Ok(answer);
                    }
                    Ok(Err(UpstreamError::Protocol(code, soa))) => {
                        return Err(UpstreamError::Protocol(code, soa));
                    }
                    Ok(Err(e)) => {
                        if message.answers.is_empty() {
                            let mut best = last_err.take();
                            select_better_error(&mut best, e);
                            return Err(best.unwrap_or(UpstreamError::Timeout));
                        }
                        return Ok(message);
                    }
                    Err(_) => {
                        if message.answers.is_empty() {
                            return Err(last_err.take().unwrap_or(UpstreamError::Timeout));
                        }
                        return Ok(message);
                    }
                }
            }
            if message.answers.is_empty() {
                return Err(last_err.take().unwrap_or(UpstreamError::Timeout));
            }
            return Ok(message);
        }

        // Every attempt ran or the deadline was already spent when the loop
        // started (a later CNAME hop reuses the shared deadline): with no
        // recorded outcome the failure is a deadline exhaustion, which is a
        // timeout condition — not the capacity-bound `NoConnections` (that
        // one always arrives via a leg error and is recorded above).
        Err(last_err.unwrap_or(UpstreamError::Timeout))
    }

    /// Resolves one query, following CNAME chains the way the old
    /// hickory-resolver did: when a response chains the queried name to
    /// another name but does not carry the requested records for the end of
    /// the chain, the target is queried again (up to `MAX_CNAME_DEPTH` hops).
    /// All hops' answers are accumulated (old `preserve_intermediates =
    /// true` semantics), so the result contains the CNAME chain plus the
    /// final records.
    ///
    /// The whole chase shares one lookup-level deadline (computed here), so
    /// a deep or cyclic chain cannot stretch the lookup by re-arming the
    /// budget per hop; the caller's outer timeout remains the final bound.
    async fn lookup_with_attempts(
        self: &Arc<Self>,
        query: &Query,
        options: &DnsRequestOptions,
        attempts: u8,
    ) -> Result<LookupAnswer, UpstreamError> {
        // Values are clamped (`MAX_CONNECT_TIMEOUT`, `ATTEMPTS_UPPER`), so
        // this cannot overflow in practice; `checked_add` guards against a
        // future caller relaxing the clamps.
        let budget = self.config.query_timeout * attempts as u32 + self.config.connect_timeout;
        let deadline = tokio::time::Instant::now()
            .checked_add(budget)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(60));

        let mut records = Vec::new();
        let mut search_name = query.name().clone();
        let mut message = self.lookup_message(query, options, attempts, deadline).await?;
        // A truncated answer (partial) surfaces with the flag so the client
        // retries over TCP; it must not be chased for CNAME or cached as
        // complete.
        if message.metadata.truncation {
            return Ok(LookupAnswer { records: message.answers, truncated: true });
        }

        // CNAME and ANY queries are answered as-is (hickory-resolver parity:
        // the old `caching_client` never chased for these types). Chasing a
        // CNAME-typed query would follow up on the target, which typically
        // answers NXDomain, discarding the CNAME records we already have.
        if query.query_type().is_any() || query.query_type().is_cname() {
            records.extend(message.answers.iter().cloned());
            return Ok(LookupAnswer { records, truncated: false });
        }

        // The first response is hop 0; every follow-up query is another hop,
        // bounded by `MAX_CNAME_DEPTH` (the old hickory-resolver limit).
        let mut hops = 0u8;
        loop {
            records.extend(message.answers.iter().cloned());

            // Fold the CNAME chain inside this response to a fixpoint:
            // answers may chain out of order (e.g. `[CNAME(mid→final),
            // CNAME(orig→mid)]`), where a single pass would miss an earlier
            // hop and chase a redundant query. The scan is bounded by the
            // number of CNAME records so a cyclic chain inside one response
            // cannot loop; the name we would need to query next is the last
            // fold target, or the original name when no CNAME matched.
            let cname_count =
                message.answers.iter().filter(|r| matches!(r.data, RData::CNAME(_))).count();
            let mut chain_end = search_name.clone();
            for _ in 0..=cname_count {
                let mut progressed = false;
                for record in &message.answers {
                    if let RData::CNAME(cname) = &record.data
                        && record.name == chain_end
                    {
                        chain_end = cname.0.clone();
                        progressed = true;
                    }
                }
                if !progressed {
                    break;
                }
            }

            if chain_end == search_name {
                // No CNAME for the current name: the answer is final.
                return Ok(LookupAnswer { records, truncated: false });
            }
            // The response already carries the requested records for the end
            // of the chain (recursive resolvers usually return CNAME + final
            // records in one response): nothing left to chase. The
            // additional section is scanned too — a completing record there
            // still completes the chain. The authority section deliberately
            // is not: it carries zone/delegation metadata (NS, SOA), and
            // treating its records as answers would let a misconfigured or
            // forged server inject answer data through it.
            let completes_chain = |record: &Record| {
                record.name == chain_end && record.record_type() == query.query_type()
            };
            let complete = message.answers.iter().any(&completes_chain)
                || message.additionals.iter().any(&completes_chain);
            if complete {
                // The chain is complete, but the completing records may live
                // in the additional section. Collect them — a "complete"
                // answer that hands the client a CNAME chain without the
                // final records would surface as "domain resolves to
                // nothing". Answer-section records were already folded into
                // `records` above; only additionals need adding, without
                // duplicating a record the answer section already carried.
                let extras: Vec<Record> = message
                    .additionals
                    .iter()
                    .filter(|record| completes_chain(record) && !records.contains(record))
                    .cloned()
                    .collect();
                records.extend(extras);
                return Ok(LookupAnswer { records, truncated: false });
            }
            if hops >= pool_config::MAX_CNAME_DEPTH {
                // Depth limit reached (e.g. a CNAME loop): return the chain
                // we accumulated instead of hanging.
                return Ok(LookupAnswer { records, truncated: false });
            }

            let next_query = Query::query(chain_end.clone(), query.query_type());
            message = match self.lookup_message(&next_query, options, attempts, deadline).await {
                Ok(message) => message,
                Err(e) => return Err(e),
            };
            search_name = chain_end;
            hops += 1;
            // A truncated follow-up hop surfaces the same way as a
            // truncated hop 0: fold in the partial records and return the
            // flag. Chasing on partial data is unreliable — the cut-off
            // tail may hold the CNAME or the final records — and reporting
            // the partial chain complete would let the caller cache it.
            if message.metadata.truncation {
                records.extend(message.answers.iter().cloned());
                return Ok(LookupAnswer { records, truncated: true });
            }
        }
    }

    /// One attempt: query up to `config.fanout` primary legs concurrently and
    /// select the outcome with a Balanced strategy — a positive answer wins
    /// immediately (the other legs are aborted), an explicit negative answer
    /// (NXDomain/NoData) waits a short grace for a positive, a truncated UDP
    /// answer is surfaced (ahead of a negative, since the stream retry may
    /// recover the full answer) so the caller retries stream-only, and
    /// transport failures are retried by the caller.
    ///
    /// When every primary leg fails with a transient error, plaintext pools
    /// fall through to their stream (TCP) legs in the same attempt — the old
    /// sequential UDP→TCP fallback, now concurrent.
    async fn attempt(
        self: &Arc<Self>,
        query: &Query,
        options: &DnsRequestOptions,
        force_stream: bool,
    ) -> Result<Message, UpstreamError> {
        let legs = self.candidate_legs(force_stream);
        match self.fan_out(query, options, &legs).await {
            FanOutVerdict::Answer(message) => Ok(message),
            FanOutVerdict::Negative(code, soa) => Err(UpstreamError::Protocol(code, soa)),
            FanOutVerdict::Truncated(message) => Ok(message),
            FanOutVerdict::Failed(e) => {
                // Explicit protocol answers (ServFail, Refused, ...) and
                // permanent TLS failures are final — matching
                // `lookup_message`'s handling of them and the module doc's
                // "an explicit protocol code is the final answer": the UDP→
                // stream fallback below is only for *transient* transport
                // errors, and re-querying a server that just answered with
                // ServFail would double its latency and load for nothing.
                if matches!(e, UpstreamError::Protocol(_, _) | UpstreamError::Tls(_)) {
                    return Err(e);
                }
                // The UDP→stream fallback only applies to the primary UDP
                // phase: a failed stream-only phase (force_stream) must not
                // re-run the same stream legs within the same attempt.
                if !force_stream && self.has_udp() {
                    let stream = rotate_capped(&self.stream_legs(), self.config.fanout);
                    if !stream.is_empty() {
                        return match self.fan_out(query, options, &stream).await {
                            FanOutVerdict::Answer(message) => Ok(message),
                            FanOutVerdict::Negative(code, soa) => {
                                Err(UpstreamError::Protocol(code, soa))
                            }
                            FanOutVerdict::Truncated(message) => Ok(message),
                            FanOutVerdict::Failed(e2) => {
                                // Both phases failed: report the more
                                // informative error instead of letting the
                                // fallback phase's error mask the primary
                                // phase's (e.g. a cap-bound NoConnections
                                // hiding a connectivity Timeout).
                                let mut best = Some(e);
                                select_better_error(&mut best, e2);
                                Err(best.unwrap())
                            }
                        };
                    }
                }
                Err(e)
            }
        }
    }

    /// Queries the given legs concurrently and applies the Balanced response
    /// selection.
    async fn fan_out(
        self: &Arc<Self>,
        query: &Query,
        options: &DnsRequestOptions,
        legs: &[usize],
    ) -> FanOutVerdict {
        let mut join_set = JoinSet::new();
        for &idx in legs {
            let pool = self.clone();
            let connector = self.connectors[idx].clone();
            let query = query.clone();
            let options = *options;
            join_set
                .spawn(async move { pool.leg_query(connector.clone(), &query, &options).await });
        }
        if join_set.is_empty() {
            return FanOutVerdict::Failed(UpstreamError::NoConnections);
        }

        let mut last_err: Option<UpstreamError> = None;
        let mut negative: Option<(ResponseCode, Option<Box<Record>>)> = None;
        let mut truncated: Option<Message> = None;
        let grace = tokio::time::sleep(pool_config::NEGATIVE_GRACE);
        tokio::pin!(grace);

        loop {
            // `biased;` makes a ready leg result win over the grace timer
            // when both fire in the same poll cycle, so a positive that
            // settles exactly at the grace boundary is not discarded.
            tokio::select! {
                biased;
                joined = join_set.join_next() => {
                    let Some(joined) = joined else {
                        // Every leg settled without a positive answer. A
                        // truncated answer outranks an explicit negative
                        // (stream retry may recover the data), so it is
                        // returned before the negative.
                        if let Some(message) = truncated {
                            return FanOutVerdict::Truncated(message);
                        }
                        if let Some((code, soa)) = negative {
                            return FanOutVerdict::Negative(code, soa);
                        }
                        return FanOutVerdict::Failed(
                            last_err.unwrap_or(UpstreamError::NoConnections),
                        );
                    };
                    if let Some(verdict) = Self::fold_leg_outcome(
                        &mut last_err,
                        &mut negative,
                        &mut truncated,
                        &mut grace,
                        joined,
                    ) {
                        // Positive answer: win immediately.
                        // The other legs are aborted mid-flight. Their
                        // connection-level failures are deliberately not
                        // recorded: an aborted query proves nothing about
                        // the connection (it may simply have been slower
                        // than the winner). A genuinely dead connection
                        // is still retired eventually — its aborted legs
                        // never update `last_used_ms`, so it goes stale
                        // and the next query races it against a fresh
                        // dial, retiring it on failure.
                        join_set.abort_all();
                        return verdict;
                    }
                }
                _ = &mut grace, if negative.is_some() => {
                    // No positive answer arrived within the grace window. A
                    // truncated UDP answer is still preferred over the
                    // negative: the stream retry may recover the full answer,
                    // so surface the truncation instead of the negative.
                    // Before aborting, harvest any leg that settled in the
                    // same poll cycle: `biased;` already prefers a ready leg
                    // result over the timer, and this drain is the backstop
                    // for results enqueued right after the select fired — a
                    // positive at the grace boundary must not be discarded.
                    while let Some(joined) = join_set.try_join_next() {
                        if let Some(verdict) = Self::fold_leg_outcome(
                            &mut last_err,
                            &mut negative,
                            &mut truncated,
                            &mut grace,
                            joined,
                        ) {
                            join_set.abort_all();
                            return verdict;
                        }
                    }
                    // Aborting the remaining legs skips their failure
                    // accounting (see the positive-answer abort above).
                    join_set.abort_all();
                    if let Some(message) = truncated {
                        return FanOutVerdict::Truncated(message);
                    }
                    let (code, soa) = negative.unwrap();
                    return FanOutVerdict::Negative(code, Self::clamp_contested_negative_ttl(soa));
                }
            }
        }
    }

    /// A negative answer that won only after the grace window (another
    /// endpoint was still in flight) may be stale: clamp its SOA TTL so the
    /// negative caching it drives (RFC 2308) expires quickly instead of
    /// poisoning the domain until the original TTL.
    fn clamp_contested_negative_ttl(mut soa: Option<Box<Record>>) -> Option<Box<Record>> {
        if let Some(record) = &mut soa {
            record.ttl = record.ttl.min(pool_config::CONTESTED_NEGATIVE_TTL);
        }
        soa
    }

    /// Folds one leg's outcome into the fan-out selection state; returns a
    /// verdict when the leg's answer wins outright (a positive answer).
    fn fold_leg_outcome(
        last_err: &mut Option<UpstreamError>,
        negative: &mut Option<(ResponseCode, Option<Box<Record>>)>,
        truncated: &mut Option<Message>,
        grace: &mut Pin<&mut tokio::time::Sleep>,
        joined: Result<Result<Message, UpstreamError>, tokio::task::JoinError>,
    ) -> Option<FanOutVerdict> {
        match joined {
            Ok(Ok(message)) => {
                if message.metadata.truncation {
                    // A truncated answer is the least desirable of the
                    // *usable* outcomes (the caller retries stream-only);
                    // keep it only if nothing better arrives.
                    if truncated.is_none() {
                        *truncated = Some(message);
                    }
                    return None;
                }
                if is_negative_response(&message) {
                    if negative.is_none() {
                        *negative =
                            Some((message.metadata.response_code, soa_of_message(&message)));
                        grace
                            .as_mut()
                            .reset(tokio::time::Instant::now() + pool_config::NEGATIVE_GRACE);
                    }
                    return None;
                }
                // Positive answer: win immediately.
                Some(FanOutVerdict::Answer(message))
            }
            Ok(Err(e)) => match &e {
                UpstreamError::Protocol(
                    code @ (ResponseCode::NXDomain | ResponseCode::NoError),
                    soa,
                ) => {
                    if negative.is_none() {
                        *negative = Some((*code, soa.clone()));
                        grace
                            .as_mut()
                            .reset(tokio::time::Instant::now() + pool_config::NEGATIVE_GRACE);
                    }
                    None
                }
                _ => {
                    select_better_error(last_err, e);
                    None
                }
            },
            // A leg task panicked: treat it as no outcome.
            Err(_) => None,
        }
    }

    /// One leg of a fan-out: reuse or dial a connection for the connector,
    /// run the query (racing a stale stream connection against a fresh dial),
    /// and record connection-level failures. Mirrors the old sequential
    /// attempt loop body.
    async fn leg_query(
        self: &Arc<Self>,
        connector: Arc<dyn DnsConnector>,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, UpstreamError> {
        // A dial failure is transient (refused, unreachable): record it and
        // let the selection layer move on to the other legs.
        let pooled = match self.acquire(connector.as_ref()).await {
            Ok(Some(pooled)) => pooled,
            Ok(None) => return Err(UpstreamError::NoConnections),
            Err(e) => return Err(e),
        };

        let stale = connector.transport() == DnsTransport::Stream
            && self.clock.now_ms().saturating_sub(pooled.last_used_ms.load(Ordering::Relaxed))
                >= self.config.stale_conn_age.as_millis() as u64;

        let (winner, result) = if stale {
            self.race(&pooled, connector.as_ref(), query, options).await
        } else {
            (pooled.clone(), self.query_once(pooled.conn.as_ref(), query, options).await)
        };

        match &result {
            Ok(_message) => {
                winner.last_used_ms.store(self.clock.now_ms(), Ordering::Relaxed);
                winner.consecutive_failures.store(0, Ordering::Relaxed);
            }
            Err(e) => {
                self.record_conn_failure(&winner, e);
                // Capacity (the multiplexer's `Busy`): this connection hit
                // its per-connection in-flight cap. Mark it used so the LRU
                // picker favours other connections, and dial one more for
                // this endpoint so load spreads across streams.
                if matches!(e, UpstreamError::NoConnections)
                    && winner.conn.transport() == DnsTransport::Stream
                {
                    winner.last_used_ms.store(self.clock.now_ms(), Ordering::Relaxed);
                    self.scale_up(connector);
                }
            }
        }
        result
    }

    /// Best-effort elastic growth: dials one more stream connection for
    /// `connector` when the pool is under `max_conns` and no scale-up dial
    /// for *that endpoint* is already in flight. Called when a multiplexed
    /// connection reports its in-flight cap (`Busy`). Failures are harmless
    /// — the next `Busy` retries.
    fn scale_up(self: &Arc<Self>, connector: Arc<dyn DnsConnector>) {
        if connector.transport() != DnsTransport::Stream || !self.can_dial(DnsTransport::Stream) {
            return;
        }
        let slot = self.dial_slot_for(connector.ip(), connector.transport());
        if slot.background_dial.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err()
        {
            return;
        }
        let pool = self.clone();
        tokio::spawn(async move {
            // The guard owns the slot's counter from here on: every exit
            // path (error, cap pressure, panic inside the dial) restores it.
            // The future is unwind-isolated like the maintenance pass so a
            // broken connector cannot kill the task with a stray panic.
            let _guard = DialGuard(&slot.background_dial);
            let conn = match catch_unwind_future(tokio::time::timeout(
                pool.config.connect_timeout,
                connector.connect(),
            ))
            .await
            {
                Ok(Ok(Ok(conn))) => conn,
                _ => return,
            };
            let pooled = Arc::new(PooledConn::new(conn, pool.clock.now_ms()));
            let mut conns = pool.conns.lock().unwrap_or_else(|e| e.into_inner());
            if pool.stream_conn_count(&conns) >= pool.config.max_conns as usize {
                drop(conns);
                pooled.conn.shutdown();
                return;
            }
            pooled.mark_pooled();
            conns.push(pooled);
        });
    }

    /// The legs a fan-out attempt starts with: the UDP connector per IP for
    /// plaintext (the fast path), or the stream connector per IP for
    /// encrypted modes. `force_stream` (UDP truncation retry) restricts to
    /// stream legs. Rotated from a random start and capped at
    /// `config.fanout`, so excess endpoints are spread across attempts.
    fn candidate_legs(&self, force_stream: bool) -> Vec<usize> {
        let legs = if force_stream {
            self.stream_legs()
        } else if self.has_udp() {
            self.udp_legs()
        } else {
            self.stream_legs()
        };
        rotate_capped(&legs, self.config.fanout)
    }

    fn has_udp(&self) -> bool {
        self.connectors.iter().any(|c| c.transport() == DnsTransport::Udp)
    }

    fn udp_legs(&self) -> Vec<usize> {
        self.connectors
            .iter()
            .enumerate()
            .filter(|(_, c)| c.transport() == DnsTransport::Udp)
            .map(|(i, _)| i)
            .collect()
    }

    fn stream_legs(&self) -> Vec<usize> {
        self.connectors
            .iter()
            .enumerate()
            .filter(|(_, c)| c.transport() == DnsTransport::Stream)
            .map(|(i, _)| i)
            .collect()
    }

    /// One query on `conn` bounded by the per-attempt budget.
    async fn query_once(
        &self,
        conn: &dyn DnsConn,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, UpstreamError> {
        tokio::time::timeout(self.config.query_timeout, conn.query(query, options))
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(from_conn_error)
    }

    /// Races a query on the stale connection against the same query on a
    /// freshly dialed connection; the first answer wins.
    ///
    /// When the fresh connection wins, the stale one is retired and the fresh
    /// one takes its place in the pool (cap-checked) — the pool self-heals
    /// without the next query paying a timeout. When the stale connection
    /// answers first it is clearly alive and the fresh dial is simply
    /// abandoned.
    ///
    /// A *transport-level* failure on the fresh leg (dial error, timeout, I/O)
    /// tells us nothing about the stale connection, so it does not retire the
    /// stale one: the stale leg's own verdict decides instead. Only an answer
    /// — success or an explicit protocol error code, which proves the server
    /// answered — lets the fresh connection take over.
    async fn race(
        &self,
        pooled: &Arc<PooledConn>,
        connector: &dyn DnsConnector,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> (Arc<PooledConn>, Result<Message, UpstreamError>) {
        let old_future = self.query_once(pooled.conn.as_ref(), query, options);
        tokio::pin!(old_future);

        // The fresh dial may complete while the stale leg is still running.
        // When the race then resolves against the stale leg (or against a
        // fresh leg that failed at the transport level), the dialed fresh
        // connection is not needed: it must be closed (the shutdown
        // contract) instead of silently dropped.
        let fresh_slot: Arc<Mutex<Option<Arc<dyn DnsConn>>>> = Arc::new(Mutex::new(None));
        let new_future = async {
            // A dial failure or timeout means the server may be unreachable;
            // stay pending so the stale connection's own verdict decides the
            // race. The dial gets its own (larger) budget, mirroring
            // `acquire`, so a hung handshake cannot hold the race open.
            let conn = match tokio::time::timeout(self.config.connect_timeout, connector.connect())
                .await
            {
                Ok(Ok(conn)) => conn,
                _ => std::future::pending().await,
            };
            *fresh_slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn.clone());
            let result = self.query_once(conn.as_ref(), query, options).await;
            (conn, result)
        };
        let mut new_future = Box::pin(new_future);

        // `biased;` polls the fresh branch first: when both legs settle in
        // the same poll cycle, a fresh answer (or explicit protocol code)
        // wins the tie. A stale connection is raced precisely because it is
        // suspected dead (usually about to time out), so letting the stale
        // side win ties would discard a valid fresh answer and burn another
        // attempt.
        tokio::select! {
            biased;
            (new_conn, new_result) = &mut new_future => match &new_result {
                Ok(_) | Err(UpstreamError::Protocol(_, _)) => {
                    // The fresh connection answered (or proved itself alive
                    // with an explicit protocol answer): the stale one is
                    // presumed dead, retire it and keep the fresh one.
                    fresh_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                    let fresh = self.retire_and_pool(pooled, new_conn);
                    (fresh, new_result)
                }
                Err(_) => {
                    // Fresh leg failed at the transport level (timeout, I/O):
                    // it proves nothing about the stale conn, so wait for the
                    // stale leg's own verdict and close the failed fresh dial.
                    if let Some(conn) = fresh_slot.lock().unwrap_or_else(|e| e.into_inner()).take()
                    {
                        conn.shutdown();
                    }
                    let old_result = old_future.await;
                    (pooled.clone(), old_result)
                }
            },
            old_result = &mut old_future => {
                // The stale conn's verdict decided the race. When it failed
                // with a transient transport error, a fresh conn that
                // already finished dialing is kept for the retry instead of
                // being thrown away: its query was cancelled with the
                // dropped future, so it is idle and healthy. When the stale
                // conn answered (it is alive) or failed permanently, the
                // dialed fresh conn is unnecessary and closed. A dial still
                // in flight is simply abandoned.
                if let Some(conn) = fresh_slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    if matches!(
                        old_result,
                        Err(UpstreamError::Timeout | UpstreamError::Internal(_))
                    ) {
                        self.pool_fresh(conn);
                    } else {
                        conn.shutdown();
                    }
                }
                (pooled.clone(), old_result)
            }
        }
    }

    /// Pools a freshly dialed connection, cap-checked; when the cap is full
    /// it is closed instead. Returns whether it was pooled.
    fn pool_fresh(&self, conn: Arc<dyn DnsConn>) -> bool {
        let pooled = Arc::new(PooledConn::new(conn, self.clock.now_ms()));
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        if self.stream_conn_count(&conns) >= self.config.max_conns as usize {
            drop(conns);
            pooled.conn.shutdown();
            return false;
        }
        pooled.mark_pooled();
        conns.push(pooled);
        true
    }

    /// Marks `old` dead, purges dead connections, and adds `fresh` to the
    /// pool (respecting the stream cap). Returns the pooled `fresh`.
    ///
    /// Only ever called from `race`, which is stream-only (UDP never races),
    /// so no UDP exemption is needed here.
    fn retire_and_pool(&self, old: &Arc<PooledConn>, fresh: Arc<dyn DnsConn>) -> Arc<PooledConn> {
        old.dead.store(true, Ordering::Relaxed);
        let fresh_pooled = Arc::new(PooledConn::new(fresh, self.clock.now_ms()));
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        let retired = Self::purge_dead(&mut conns);
        if self.stream_conn_count(&conns) < self.config.max_conns as usize {
            fresh_pooled.mark_pooled();
            conns.push(fresh_pooled.clone());
        }
        // When the cap is full the fresh connection is not pooled: it still
        // serves this query and `PooledConn`'s Drop closes it afterwards.
        drop(conns);
        for pooled in retired {
            pooled.conn.shutdown();
        }
        fresh_pooled
    }

    /// Removes dead connections from `conns`, returning the retired ones so
    /// the caller can `shutdown()` them outside the lock. Every purge path
    /// (`acquire`, `retire_and_pool`, `maintain`) goes through here so the
    /// shutdown contract stays uniform.
    fn purge_dead(conns: &mut Vec<Arc<PooledConn>>) -> Vec<Arc<PooledConn>> {
        let mut retired = Vec::new();
        conns.retain(|pooled| {
            if pooled.dead.load(Ordering::Relaxed) {
                retired.push(pooled.clone());
                false
            } else {
                true
            }
        });
        retired
    }

    /// The live, non-dead connection for `connector`'s endpoint with the
    /// oldest `last_used` (LRU), if any. Dead connections are purged inline
    /// (and shut down) so cap accounting stays exact even between
    /// maintenance ticks. A connection is only reusable by connectors of
    /// the same transport: after a UDP truncation the TCP connector must
    /// dial a real TCP connection instead of reusing the (same-IP) UDP one.
    fn find_reusable(&self, connector: &dyn DnsConnector) -> Option<Arc<PooledConn>> {
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        let retired = Self::purge_dead(&mut conns);
        let existing = conns
            .iter()
            .filter(|pooled| {
                pooled.conn.ip() == connector.ip()
                    && pooled.conn.transport() == connector.transport()
                    && !pooled.dead.load(Ordering::Relaxed)
            })
            .min_by_key(|pooled| pooled.last_used_ms.load(Ordering::Relaxed))
            .cloned();
        drop(conns);
        for pooled in &retired {
            pooled.conn.shutdown();
        }
        existing
    }

    /// The dial state for an endpoint (see [`DialSlot`]): the cold-dial
    /// single-flight gate plus the background scale-up dial slot.
    fn dial_slot_for(&self, ip: IpAddr, transport: DnsTransport) -> Arc<DialSlot> {
        let mut slots = self.dial_slots.lock().unwrap_or_else(|e| e.into_inner());
        slots.entry((ip, transport)).or_insert_with(|| Arc::new(DialSlot::default())).clone()
    }

    /// Picks a usable pooled connection for `connector`, or dials a new one
    /// when the pool is under its cap. Returns `None` when the connector is
    /// temporarily undialable and the pool must move on.
    async fn acquire(
        &self,
        connector: &dyn DnsConnector,
    ) -> Result<Option<Arc<PooledConn>>, UpstreamError> {
        let result = self.acquire_inner(connector).await;
        // Stamp the borrow (completion stamps `last_used_ms` in `leg_query`):
        // the maintenance pass judges idleness by both stamps, so a query in
        // flight on an almost-idle connection cannot be reaped — and for
        // DoQ, actively closed — under the query. The staleness check must
        // observe the *completion* stamp, which the borrow does not touch.
        if let Ok(Some(pooled)) = &result {
            pooled.last_borrow_ms.store(self.clock.now_ms(), Ordering::Relaxed);
        }
        result
    }

    async fn acquire_inner(
        &self,
        connector: &dyn DnsConnector,
    ) -> Result<Option<Arc<PooledConn>>, UpstreamError> {
        // Fast path: reuse a live, non-dead connection for this endpoint.
        if let Some(pooled) = self.find_reusable(connector) {
            return Ok(Some(pooled));
        }

        if !self.can_dial(connector.transport()) {
            return Ok(None);
        }

        // Cold-dial single-flight: when another task is already dialing
        // this endpoint, wait for its turn (bounded by the same budget a
        // cold dial gets) and prefer its pooled result — a burst of C
        // concurrent lookups on a cold pool costs one handshake instead of
        // C. When the in-flight dial failed, take the next turn and dial
        // ourselves (serialized retries, never worse than the un-gated
        // behavior).
        let slot = self.dial_slot_for(connector.ip(), connector.transport());
        let _turn = match slot.gate.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                let turn = match tokio::time::timeout(self.config.connect_timeout, slot.gate.lock())
                    .await
                {
                    Ok(turn) => turn,
                    Err(_) => {
                        // The turn holder's dial may have landed in the
                        // microseconds before our deadline expired — one
                        // last look before giving up.
                        if let Some(pooled) = self.find_reusable(connector) {
                            return Ok(Some(pooled));
                        }
                        // Queuing behind a cold dial that outlived its
                        // own budget is congestion, not a connectivity
                        // verdict: surface the capacity class (`None` →
                        // `NoConnections`), which the pool never counts
                        // against the upstream's health. Reporting a
                        // `Timeout` here would let a healthy-but-slow
                        // endpoint be voted offline by its own queue.
                        return Ok(None);
                    }
                };
                if let Some(pooled) = self.find_reusable(connector) {
                    return Ok(Some(pooled));
                }
                turn
            }
        };
        // The turn's previous holder (or a concurrent waiter between our
        // first check and the turn) may have pooled a connection already.
        if let Some(pooled) = self.find_reusable(connector) {
            return Ok(Some(pooled));
        }

        let conn = tokio::time::timeout(self.config.connect_timeout, connector.connect())
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(from_conn_error)?;

        let pooled = Arc::new(PooledConn::new(conn, self.clock.now_ms()));
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        // Another task may have dialed while we were connecting, pushing us
        // over `max_conns` (UDP sockets are cheap and exempt). In that race,
        // the connection we just built is not pooled; it still serves this
        // query (use-then-drop) so cap pressure never fails a query that has
        // a live connection in hand. Only a connection to the same endpoint
        // is a valid pooled fallback — reusing a different server's
        // connection would send this query to the wrong upstream.
        if connector.transport() == DnsTransport::Stream
            && self.stream_conn_count(&conns) >= self.config.max_conns as usize
        {
            tracing::debug!(upstream_id = %self.upstream_id, "dropping extra stream connection (pool cap reached)");
            if let Some(existing) = conns
                .iter()
                .filter(|p| {
                    p.conn.ip() == connector.ip()
                        && p.conn.transport() == connector.transport()
                        && !p.dead.load(Ordering::Relaxed)
                })
                .min_by_key(|p| p.last_used_ms.load(Ordering::Relaxed))
                .cloned()
            {
                drop(conns);
                // The connection we just built will not serve this query:
                // closing it is handled by `PooledConn`'s Drop (it was
                // never pooled) so the shutdown contract holds.
                return Ok(Some(existing));
            }
            return Ok(Some(pooled));
        }
        pooled.mark_pooled();
        conns.push(pooled.clone());
        Ok(Some(pooled))
    }

    /// True while the pool may dial another connection for `transport`.
    fn can_dial(&self, transport: DnsTransport) -> bool {
        let conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        transport == DnsTransport::Udp
            || self.stream_conn_count(&conns) < self.config.max_conns as usize
    }

    fn stream_conn_count(&self, conns: &[Arc<PooledConn>]) -> usize {
        conns.iter().filter(|p| p.conn.transport() == DnsTransport::Stream).count()
    }

    /// Records a failed query on `pooled`; retires it after the
    /// transport-appropriate `CONN_FAILURE_THRESHOLD_*` consecutive
    /// connectivity failures so the next attempt dials a fresh connection.
    /// Explicit protocol answers (NXDomain, ServFail, ...) prove the
    /// connection is alive and never count; capacity conditions
    /// (`NoConnections`, e.g. the multiplexer's `Busy` signal) say nothing
    /// about the connection either and never count; permanent TLS failures
    /// (bad certificate) would fail on any connection, so retiring this one
    /// would only trigger a pointless re-dial and never count.
    fn record_conn_failure(&self, pooled: &Arc<PooledConn>, err: &UpstreamError) {
        if matches!(
            err,
            UpstreamError::Protocol(_, _) | UpstreamError::NoConnections | UpstreamError::Tls(_)
        ) {
            return;
        }
        let failures = pooled.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        let threshold = match pooled.conn.transport() {
            DnsTransport::Udp => pool_config::CONN_FAILURE_THRESHOLD_UDP,
            DnsTransport::Stream => pool_config::CONN_FAILURE_THRESHOLD_STREAM,
        };
        if failures >= threshold {
            pooled.dead.store(true, Ordering::Relaxed);
            tracing::warn!(
                flow_id = self.flow_id,
                dns_mark = self.dns_mark,
                upstream_id = %self.upstream_id,
                ip = %pooled.conn.ip(),
                %err,
                "retiring connection after {failures} consecutive failures"
            );
        }
    }

    /// One-shot warm-up at pool build time: immediately dials up to
    /// `min_conns` stream connections (round-robin across endpoints) so the
    /// first real query does not pay a cold TLS/QUIC handshake. Runs until
    /// the pool is dropped (Weak upgrade fails).
    fn spawn_warmup(self: &Arc<Self>) {
        if self.config.min_conns == 0 {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let Some(pool) = weak.upgrade() else {
                return;
            };
            // Panic-isolated like the maintenance loop: a broken connector
            // must not turn the build-time warm-up into a silent crash.
            // The maintenance task retries warm-up on its next tick.
            if let Err(panic) = catch_unwind_future(pool.warm_up_to_min()).await {
                tracing::warn!("warm-up pass panicked: {panic:?}");
            }
        });
    }

    /// Dials one warm stream connection per stream endpoint (round-robin),
    /// stopping once the pool holds `min_conns` of them. The pool is
    /// multiplexed — one connection per endpoint serves all queries — so
    /// `min_conns` is effectively capped at the number of stream endpoints,
    /// and reusing an existing connection never counts as progress. The loop
    /// is therefore bounded even when `min_conns` exceeds the endpoint count.
    async fn warm_up_to_min(&self) {
        let stream_idx: Vec<usize> = self
            .connectors
            .iter()
            .enumerate()
            .filter(|(_, c)| c.transport() == DnsTransport::Stream)
            .map(|(i, _)| i)
            .collect();
        for &i in &stream_idx {
            let stream_conns = self
                .conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|p| p.conn.transport() == DnsTransport::Stream)
                .count();
            if stream_conns >= self.config.min_conns as usize {
                return;
            }
            match self.acquire(self.connectors[i].as_ref()).await {
                Ok(Some(_)) => {}
                // Stream cap reached: nothing more to dial this pass; the
                // maintenance task retries on its next tick.
                Ok(None) => return,
                // Dial failure on this endpoint: keep warming the others
                // instead of letting one dead endpoint starve them.
                Err(_) => continue,
            }
        }
    }

    /// Background task: periodically prunes dead/idle connections and keeps
    /// the pool at `min_conns` (warm-up). Offline revival runs on its own
    /// probe loop (see [`UpstreamPool::spawn_revival_probes`]). Runs until
    /// the pool is dropped (Weak upgrade fails).
    fn spawn_maintenance(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                // Sleep first, then check liveness: holding the upgraded
                // Arc across the sleep would keep a dropped pool alive for
                // one extra pass that dials warm-up connections nobody
                // references. If the pool is gone when the sleep ends, the
                // upgrade fails and the task exits without a final pass.
                tokio::time::sleep(pool_config::MAINTENANCE_INTERVAL).await;
                let Some(pool) = weak.upgrade() else {
                    return;
                };
                pool.maintain_guarded().await;
            }
        });
    }

    /// One maintenance pass, panic-isolated. The task is the pool's only
    /// reaper, warmer and prober: a panicking pass (a broken connector, a
    /// violated invariant) must be logged and swallowed — tokio catches
    /// task panics, so an unguarded pass would silently kill the loop and
    /// idle connections would leak forever while an offline upstream is
    /// never probed again.
    async fn maintain_guarded(self: &Arc<Self>) {
        if let Err(panic) = catch_unwind_future(self.maintain()).await {
            tracing::error!("maintenance pass panicked: {panic:?}");
        }
    }

    async fn maintain(self: &Arc<Self>) {
        tracing::debug!(upstream_id = %self.upstream_id, snapshot = ?self.snapshot(), "upstream maintenance pass");
        // 1. Prune dead connections; drop idle connections beyond the
        //    `min_conns` most recently used stream ones. UDP entries are
        //    bookkeeping over stateless per-query sockets, so every idle UDP
        //    entry is reappable — without this, cold-start bursts that raced
        //    `find_reusable` would leave entries behind forever and every
        //    hot-path scan under the `conns` lock would keep degrading.
        let mut retired = Vec::new();
        {
            let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
            let now = self.clock.now_ms();
            let min_conns = self.config.min_conns as usize;
            retired.extend(Self::purge_dead(&mut conns));

            let idle: Vec<Arc<PooledConn>> = conns
                .iter()
                .filter(|pooled| {
                    // Both activity stamps count: a connection whose query
                    // completed long ago but was just borrowed (query in
                    // flight) is not idle.
                    now.saturating_sub(pooled.last_active_ms())
                        > self.config.idle_timeout.as_millis() as u64
                })
                .cloned()
                .collect();
            let (idle_streams, idle_udp): (Vec<Arc<PooledConn>>, Vec<Arc<PooledConn>>) = idle
                .into_iter()
                .partition(|pooled| pooled.conn.transport() == DnsTransport::Stream);
            let stream_count =
                conns.iter().filter(|p| p.conn.transport() == DnsTransport::Stream).count();
            let non_idle_streams = stream_count - idle_streams.len();
            // We may reap any idle stream connection as long as `min_conns`
            // stream connections remain; prefer reaping the longest-idle
            // ones. Idle UDP entries have no warm-up notion and are all
            // removable.
            let removable =
                idle_streams.len().saturating_sub(min_conns.saturating_sub(non_idle_streams));
            let mut idle_streams = idle_streams;
            if removable > 0 {
                idle_streams.sort_by_key(|p| p.last_used_ms.load(Ordering::Relaxed));
                for pooled in idle_streams.into_iter().take(removable) {
                    conns.retain(|p| !Arc::ptr_eq(p, &pooled));
                    retired.push(pooled);
                }
            }
            for pooled in idle_udp {
                conns.retain(|p| !Arc::ptr_eq(p, &pooled));
                retired.push(pooled);
            }
        }
        for pooled in retired {
            pooled.conn.shutdown();
        }

        // 2. Warm-up: top the pool back up to `min_conns` stream connections.
        self.warm_up_to_min().await;
    }

    /// Spawns the revival probe loop after the upstream flipped offline:
    /// probes immediately, then re-probes every `probe_interval` until the
    /// upstream answers (success or an explicit protocol code — anything
    /// else proves nothing) or the pool is dropped. The loop is detached
    /// from any client query, so a dropped lookup can never strand the
    /// offline state; it exits on its own once `offline` clears.
    fn spawn_revival_probes(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(pool) = weak.upgrade() else {
                    return;
                };
                if !pool.health.offline.load(Ordering::Relaxed) {
                    return;
                }
                // Panic-isolated like the maintenance pass: a broken
                // connector must not kill the revival loop.
                if let Err(panic) = catch_unwind_future(pool.revival_probe()).await {
                    tracing::warn!("revival probe panicked: {panic:?}");
                }
                // Don't hold the pool across the interval sleep: a dropped
                // pool must be reaped without waiting out the interval.
                let interval = pool.config.probe_interval;
                drop(pool);
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// One revival probe: an NS query for the root zone through the same
    /// attempt path as real lookups (shared deadline, fan-out, UDP→stream
    /// fallback). The revival criterion matches client lookups: any
    /// explicit answer (success or a protocol code) proves the upstream is
    /// alive; transport-level failures keep it offline.
    async fn revival_probe(self: &Arc<Self>) {
        let Ok(name) = Name::from_str(".") else { return };
        let query = Query::query(name, RecordType::NS);
        let options = request_options();
        match self.attempt(&query, &options, false).await {
            Ok(_) | Err(UpstreamError::Protocol(_, _)) => self.health.record_success(),
            Err(_) => {}
        }
    }
}

/// Per-attempt query options, matching the old resolver's defaults
/// (recursion desired, EDNS0 with the modern 1232-byte payload).
fn request_options() -> DnsRequestOptions {
    let mut options = DnsRequestOptions::default();
    options.recursion_desired = true;
    options.use_edns = true;
    options.edns_payload_len = hickory_proto::op::DEFAULT_MAX_PAYLOAD_LEN;
    options
}

/// Maps a connection error to the pool's taxonomy.
fn from_conn_error(e: traits::DnsConnError) -> UpstreamError {
    match e {
        traits::DnsConnError::Timeout => UpstreamError::Timeout,
        traits::DnsConnError::Io(msg) => UpstreamError::Internal(msg),
        traits::DnsConnError::NoConnections => UpstreamError::NoConnections,
        traits::DnsConnError::Protocol(code, soa) => UpstreamError::Protocol(code, soa),
        traits::DnsConnError::Tls(msg) => UpstreamError::Tls(msg),
        traits::DnsConnError::Internal(msg) => UpstreamError::Internal(msg),
    }
}

/// Runs a future to completion, catching any panic raised inside it
/// (e.g. a broken connector) so background loops can log and keep running
/// instead of dying silently.
async fn catch_unwind_future<F: std::future::Future>(
    future: F,
) -> Result<F::Output, Box<dyn std::any::Any + Send>> {
    futures_util::future::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(future)).await
}

#[cfg(test)]
mod tests;
