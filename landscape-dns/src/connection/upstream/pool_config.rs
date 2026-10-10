//! Per-upstream pooling parameters: mode-aware defaults with optional
//! overrides from [`PoolSettings`] (all values clamped).
//!
//! `PoolSettings` is deliberately *not* part of the public configuration yet:
//! the pool always runs with `PoolSettings::default()` (all `None` → fixed
//! mode-aware defaults). It will be wired into `DnsUpstreamConfig` in a future
//! change so per-upstream tuning can be exposed; only this module and the
//! `UpstreamPool::new` call sites need to change then.

use std::time::Duration;

use landscape_common::dns::upstream::DnsUpstreamMode;

/// Optional per-upstream connection-pool tuning. `None` fields fall back to
/// the fixed mode-aware defaults in [`PoolConfig::for_mode`].
#[derive(Debug, Clone, Default, Hash)]
pub(crate) struct PoolSettings {
    /// Minimum connections kept warm (pre-connected at pool build time;
    /// encrypted modes default to 1). UDP never pre-connects.
    pub min_conns: Option<u16>,
    /// Maximum stream connections per upstream (UDP sockets are exempt).
    pub max_conns: Option<u16>,
    /// Idle connections are reaped after this many seconds of inactivity
    /// (never below `min_conns`).
    pub idle_timeout_secs: Option<u64>,
    /// Budget in milliseconds for establishing a *new* connection (TCP
    /// connect + TLS/QUIC handshake). Larger than the per-attempt query
    /// timeout so cold handshakes no longer eat into the query budget.
    pub connect_timeout_ms: Option<u64>,
    /// Query attempts per lookup before failing.
    pub attempts: Option<u8>,
    /// Maximum number of upstream endpoints queried concurrently per attempt
    /// (each IP is queried once; plaintext uses UDP, encrypted modes use the
    /// stream connection). Excess endpoints rotate in on later attempts.
    pub max_fanout: Option<u8>,
    /// Send QUIC keep-alives so the connection survives idle periods instead
    /// of silently dying on the negotiated idle timeout (quinn defaults to
    /// 30s). Only meaningful for DoQ upstreams; other modes ignore it.
    pub keep_alive: Option<bool>,
}

/// Timeout applied to a single query attempt on one connection.
pub(crate) const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(1);
/// How many attempts a lookup gets before failing (matches the old hickory
/// `ResolverOpts.attempts`).
pub(crate) const DEFAULT_ATTEMPTS: u8 = 3;
/// Budget for establishing a *new* connection (TCP connect, TLS/DoH/DoQ
/// handshake). This is deliberately larger than the query timeout so a cold
/// handshake no longer eats into the query budget, but small enough that the
/// lookup-level budget (`attempts × query_timeout + connect_timeout` = 5s
/// with the defaults) stays within the caller's outer lookup timeout.
pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Idle connections older than this are reaped by the background maintenance
/// task. QUIC connections otherwise die silently on their own idle timeout,
/// turning the next query into a cold handshake.
pub(crate) const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Maintenance cadence of the background task.
pub(crate) const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(10);
/// How long a stream transport may park a query waiting for an in-flight
/// slot the *peer's* advertised concurrency limit keeps closed (h2
/// SETTINGS_MAX_CONCURRENT_STREAMS / QUIC bidi-stream limit below our own
/// `max_active_requests` cap). After the wait the query surfaces the
/// capacity class (`NoConnections`) so the pool dials another connection
/// instead of letting the queue age into a health-counted `Timeout`.
pub(crate) const STREAM_CAPACITY_WAIT: Duration = Duration::from_millis(50);
/// Consecutive connectivity failures before a UDP connection is retired from
/// the pool. UDP sockets are cheap to replace, so a single failure (e.g. a
/// lost packet) retires the socket immediately.
pub(crate) const CONN_FAILURE_THRESHOLD_UDP: u32 = 1;
/// Consecutive connectivity failures before a stream connection is retired
/// from the pool. Stream connections amortize an expensive handshake, so a
/// single transient timeout must not force a fresh TLS/QUIC handshake; two
/// consecutive failures prove the connection is really dead.
pub(crate) const CONN_FAILURE_THRESHOLD_STREAM: u32 = 2;
/// Consecutive failures before the whole upstream is marked offline and
/// queries are refused (until a probe revives it).
pub(crate) const UPSTREAM_FAILURE_THRESHOLD: u32 = 3;
/// Gap between revival probes while the upstream is offline. The revival
/// probe loop probes once at flip time and then once per interval until
/// the upstream answers.
pub(crate) const PROBE_INTERVAL: Duration = Duration::from_secs(3);
/// A connection idle for longer than this is treated as suspect (servers
/// silently drop idle connections); the next query on it races against a
/// freshly dialed one and the first answer wins.
pub(crate) const STALE_CONN_AGE: Duration = Duration::from_secs(30);

/// Cap on concurrent in-flight requests per multiplexed connection. This is
/// deliberately larger than the old hickory-resolver's `num_concurrent_reqs`
/// (4): the pool multiplexes every query of one endpoint over a single
/// stream connection, and a fan-out of up to 8 legs plus concurrent client
/// lookups can easily exceed 4 in-flight requests. The cap still bounds
/// worst-case memory and the `Busy` pressure it causes is classified as a
/// capacity condition (never counted against the connection or the
/// upstream's health).
const MAX_ACTIVE_REQUESTS: usize = 32;

/// Hard bounds for user-provided values.
const MIN_CONNS_CAP: u16 = 4;
const MAX_CONNS_LOWER: u16 = 1;
const MAX_CONNS_UPPER: u16 = 16;
const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
/// Upper bound for the connect budget: the lookup-level deadline adds it to
/// `attempts × query_timeout`, and `tokio::time::Instant + Duration` panics
/// on overflow — a huge value must not be able to reach that arithmetic.
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPTS_LOWER: u8 = 1;
const ATTEMPTS_UPPER: u8 = 5;
const FANOUT_LOWER: u8 = 1;
const FANOUT_UPPER: u8 = 8;

/// Default number of endpoints queried concurrently per attempt.
pub(crate) const DEFAULT_FANOUT: usize = 4;

/// An explicit negative answer (NXDomain/NoData) waits this long for a
/// positive answer from another concurrently queried endpoint before being
/// returned
pub(crate) const NEGATIVE_GRACE: Duration = Duration::from_millis(100);

/// TTL clamp applied to the SOA of a negative answer that won only after the
/// grace window (another endpoint was still in flight and might have answered
/// positively). RFC 2308 negative caching keys off the SOA, so clamping it
/// makes a possibly-stale negative expire quickly instead of poisoning the
/// domain until its original TTL.
pub(crate) const CONTESTED_NEGATIVE_TTL: u32 = 1;

/// Maximum number of CNAME hops a lookup follows (the old hickory-resolver
/// used the same limit).
pub(crate) const MAX_CNAME_DEPTH: u8 = 8;

#[derive(Debug, Clone)]
pub(crate) struct PoolConfig {
    /// Per-attempt query timeout.
    pub query_timeout: Duration,
    /// Budget for establishing a new connection.
    pub connect_timeout: Duration,
    /// Query attempts per lookup.
    pub attempts: u8,
    /// Minimum connections kept warm (pre-connected at pool build time).
    /// Applied per pool, effectively capped at the stream endpoint count.
    pub min_conns: u16,
    /// Maximum stream connections per upstream, counted across all
    /// endpoints (one endpoint may not exceed the budget either; UDP
    /// sockets are exempt from the cap).
    pub max_conns: u16,
    /// Idle connections are reaped after this long (never below `min_conns`).
    pub idle_timeout: Duration,
    /// Cap on concurrent in-flight requests per multiplexed connection.
    pub max_active_requests: usize,
    /// Minimum gap between real attempts while the upstream is offline
    /// (in-band probing).
    pub probe_interval: Duration,
    /// A connection idle for longer than this is raced against a fresh dial.
    pub stale_conn_age: Duration,
    /// Maximum number of endpoints queried concurrently per attempt.
    pub fanout: usize,
    /// QUIC keep-alives (only DoQ connectors read this).
    pub keep_alive: bool,
}

impl PoolConfig {
    /// Builds a config for the given upstream mode, applying mode-aware
    /// defaults plus the optional user overrides (clamped to sane bounds;
    /// nothing here can fail). A `PoolSettings::default()` (all `None`) yields
    /// exactly the fixed defaults.
    pub fn from_settings(mode: &DnsUpstreamMode, settings: &PoolSettings) -> Self {
        let mut config = Self::for_mode(mode);
        if let Some(min_conns) = settings.min_conns {
            config.min_conns = min_conns.min(MIN_CONNS_CAP);
        }
        if let Some(max_conns) = settings.max_conns {
            config.max_conns = max_conns.clamp(MAX_CONNS_LOWER, MAX_CONNS_UPPER);
        }
        if let Some(idle_timeout_secs) = settings.idle_timeout_secs {
            config.idle_timeout = Duration::from_secs(idle_timeout_secs).max(MIN_IDLE_TIMEOUT);
        }
        if let Some(connect_timeout_ms) = settings.connect_timeout_ms {
            config.connect_timeout = Duration::from_millis(connect_timeout_ms)
                .clamp(MIN_CONNECT_TIMEOUT, MAX_CONNECT_TIMEOUT);
        }
        if let Some(attempts) = settings.attempts {
            config.attempts = attempts.clamp(ATTEMPTS_LOWER, ATTEMPTS_UPPER);
        }
        if let Some(max_fanout) = settings.max_fanout {
            config.fanout = max_fanout.clamp(FANOUT_LOWER, FANOUT_UPPER) as usize;
        }
        if let Some(keep_alive) = settings.keep_alive {
            config.keep_alive = keep_alive;
        }
        config
    }

    /// Builds the fixed mode-aware defaults: encrypted modes keep one
    /// connection warm by default so the first query after a rebuild does
    /// not pay a cold TLS/QUIC handshake. DoQ additionally keeps its
    /// connection alive (quinn's default idle timeout is 30s; without
    /// keep-alives the next query after an idle period pays a fresh
    /// handshake).
    pub fn for_mode(mode: &DnsUpstreamMode) -> Self {
        let min_conns = match mode {
            DnsUpstreamMode::Plaintext => 0,
            DnsUpstreamMode::Tls { .. }
            | DnsUpstreamMode::Https { .. }
            | DnsUpstreamMode::Quic { .. } => 1,
        };
        let keep_alive = matches!(mode, DnsUpstreamMode::Quic { .. });
        Self {
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            min_conns,
            max_conns: DEFAULT_MAX_CONNS,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_active_requests: MAX_ACTIVE_REQUESTS,
            probe_interval: PROBE_INTERVAL,
            stale_conn_age: STALE_CONN_AGE,
            fanout: DEFAULT_FANOUT,
            keep_alive,
        }
    }
}

/// Default per-pool stream-connection ceiling (`for_mode` value).
pub(crate) const DEFAULT_MAX_CONNS: u16 = 4;

/// QUIC keep-alive cadence for a given idle timeout, clamped to sane
/// bounds. Only DoQ connectors use this.
///
/// The cadence is derived from the *locally configured* idle timeout; the
/// negotiated timeout is the minimum of both peers' `max_idle_timeout`, so
/// a peer advertising a timeout below `3 × cadence` can still reap the
/// connection between keep-alives (quinn exposes no getter for the
/// negotiated value). The upper bound is deliberately below quinn's client
/// default `max_idle_timeout` (30s) so the common case beats the idle
/// timer instead of racing it.
pub(crate) fn keep_alive_interval(idle_timeout: Duration) -> Duration {
    (idle_timeout / 3).clamp(Duration::from_secs(1), KEEP_ALIVE_MAX)
}

/// Upper bound for the QUIC keep-alive cadence (see [`keep_alive_interval`]).
/// Deliberately conservative: the negotiated idle timeout is the minimum of
/// both peers' `max_idle_timeout` and quinn exposes no getter for it, so
/// a peer advertising a low timeout can still reap the connection between
/// keep-alives — a smaller bound narrows that window.
pub(crate) const KEEP_ALIVE_MAX: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(
        min_conns: Option<u16>,
        max_conns: Option<u16>,
        idle_timeout_secs: Option<u64>,
        connect_timeout_ms: Option<u64>,
        attempts: Option<u8>,
        max_fanout: Option<u8>,
    ) -> PoolSettings {
        PoolSettings {
            min_conns,
            max_conns,
            idle_timeout_secs,
            connect_timeout_ms,
            attempts,
            max_fanout,
            keep_alive: None,
        }
    }

    /// All-`None` settings must yield exactly the fixed defaults — asserted
    /// against the named constants rather than `for_mode`, so drift on
    /// either side fails here instead of the test mirroring itself.
    #[test]
    fn default_settings_match_fixed_defaults() {
        let modes = [
            DnsUpstreamMode::Plaintext,
            DnsUpstreamMode::Tls { domain: "dns.example".into() },
            DnsUpstreamMode::Https { domain: "dns.example".into(), http_endpoint: None },
            DnsUpstreamMode::Quic { domain: "dns.example".into() },
        ];
        for mode in &modes {
            let cfg = PoolConfig::from_settings(mode, &PoolSettings::default());
            assert_eq!(cfg.query_timeout, DEFAULT_QUERY_TIMEOUT);
            assert_eq!(cfg.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
            assert_eq!(cfg.attempts, DEFAULT_ATTEMPTS);
            assert_eq!(cfg.max_conns, DEFAULT_MAX_CONNS);
            assert_eq!(cfg.idle_timeout, DEFAULT_IDLE_TIMEOUT);
            assert_eq!(cfg.probe_interval, PROBE_INTERVAL);
            assert_eq!(cfg.stale_conn_age, STALE_CONN_AGE);
            assert_eq!(cfg.fanout, DEFAULT_FANOUT);
            // Mode-dependent values: encrypted modes warm one connection,
            // only DoQ keeps alive.
            let encrypted = !matches!(mode, DnsUpstreamMode::Plaintext);
            assert_eq!(cfg.min_conns, u16::from(encrypted));
            assert_eq!(cfg.keep_alive, matches!(mode, DnsUpstreamMode::Quic { .. }));
        }
    }

    /// Plaintext never pre-connects; encrypted modes warm one connection.
    #[test]
    fn min_conns_is_mode_aware() {
        let plaintext = PoolConfig::for_mode(&DnsUpstreamMode::Plaintext);
        assert_eq!(plaintext.min_conns, 0);

        for mode in [
            DnsUpstreamMode::Tls { domain: "dns.example".into() },
            DnsUpstreamMode::Https { domain: "dns.example".into(), http_endpoint: None },
            DnsUpstreamMode::Quic { domain: "dns.example".into() },
        ] {
            let config = PoolConfig::for_mode(&mode);
            assert_eq!(config.min_conns, 1);
        }
    }

    #[test]
    fn min_conns_clamped_to_upper_cap() {
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(Some(2), None, None, None, None, None))
                .min_conns,
            2
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(Some(99), None, None, None, None, None))
                .min_conns,
            MIN_CONNS_CAP
        );
    }

    #[test]
    fn max_conns_clamped_to_lower_and_upper_bounds() {
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, Some(8), None, None, None, None))
                .max_conns,
            8
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, Some(0), None, None, None, None))
                .max_conns,
            MAX_CONNS_LOWER
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, Some(100), None, None, None, None))
                .max_conns,
            MAX_CONNS_UPPER
        );
    }

    #[test]
    fn attempts_clamped_to_lower_and_upper_bounds() {
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, None, Some(3), None))
                .attempts,
            3
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, None, Some(0), None))
                .attempts,
            ATTEMPTS_LOWER
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, None, Some(99), None))
                .attempts,
            ATTEMPTS_UPPER
        );
    }

    #[test]
    fn idle_timeout_floored_at_minimum() {
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, Some(1), None, None, None))
                .idle_timeout,
            MIN_IDLE_TIMEOUT
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, Some(120), None, None, None))
                .idle_timeout,
            Duration::from_secs(120)
        );
    }

    #[test]
    fn connect_timeout_floored_at_minimum() {
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, Some(50), None, None))
                .connect_timeout,
            MIN_CONNECT_TIMEOUT
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, Some(5000), None, None))
                .connect_timeout,
            Duration::from_millis(5000)
        );
    }

    #[test]
    fn connect_timeout_clamped_to_upper_bound() {
        // A huge connect budget must be clamped: the lookup-level deadline
        // adds it to `attempts × query_timeout`, and an unbounded value
        // could overflow the `Instant` arithmetic in `lookup_with_attempts`.
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(
                &base,
                &settings(None, None, None, Some(u64::MAX / 2), None, None)
            )
            .connect_timeout,
            MAX_CONNECT_TIMEOUT
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, Some(10000), None, None))
                .connect_timeout,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn max_fanout_clamped_to_lower_and_upper_bounds() {
        let base = DnsUpstreamMode::Plaintext;
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, None, None, Some(3)))
                .fanout,
            3
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, None, None, Some(0)))
                .fanout,
            FANOUT_LOWER as usize
        );
        assert_eq!(
            PoolConfig::from_settings(&base, &settings(None, None, None, None, None, Some(99)))
                .fanout,
            FANOUT_UPPER as usize
        );
    }

    /// The pool's worst-case internal lookup budget must leave headroom under
    /// the caller's outer envelope (`LOOKUP_TIMEOUT` in `server::chain`, 6s).
    /// With equal budgets the caller's timeout fires at the exact moment the
    /// pool's final attempt completes and the answer is discarded; the margin
    /// here covers that final attempt plus response propagation. Bump this
    /// test together with either side of the equation.
    #[test]
    fn default_budget_leaves_caller_margin() {
        for mode in [
            DnsUpstreamMode::Plaintext,
            DnsUpstreamMode::Tls { domain: "dns.example".into() },
            DnsUpstreamMode::Https { domain: "dns.example".into(), http_endpoint: None },
            DnsUpstreamMode::Quic { domain: "dns.example".into() },
        ] {
            let config = PoolConfig::for_mode(&mode);
            let budget = config.query_timeout * config.attempts as u32 + config.connect_timeout;
            assert!(
                budget < crate::server::chain::LOOKUP_TIMEOUT,
                "pool internal budget {budget:?} must be below the caller's LOOKUP_TIMEOUT"
            );
        }
    }

    /// DoQ keeps its connection alive by default (quinn's 30s idle timeout
    /// would otherwise silently kill it); every other mode does not.
    #[test]
    fn keep_alive_defaults_to_quic_only() {
        assert!(!PoolConfig::for_mode(&DnsUpstreamMode::Plaintext).keep_alive);
        assert!(
            !PoolConfig::for_mode(&DnsUpstreamMode::Tls { domain: "dns.example".into() })
                .keep_alive
        );
        assert!(
            !PoolConfig::for_mode(&DnsUpstreamMode::Https {
                domain: "dns.example".into(),
                http_endpoint: None,
            })
            .keep_alive
        );
        assert!(
            PoolConfig::for_mode(&DnsUpstreamMode::Quic { domain: "dns.example".into() })
                .keep_alive
        );
    }

    /// The explicit `PoolSettings` override wins over the mode default in
    /// both directions.
    #[test]
    fn keep_alive_override_wins() {
        let quic = DnsUpstreamMode::Quic { domain: "dns.example".into() };
        let plaintext = DnsUpstreamMode::Plaintext;
        let on = settings(None, None, None, None, None, None);
        let on = PoolSettings { keep_alive: Some(true), ..on };
        let off = PoolSettings { keep_alive: Some(false), ..on.clone() };
        assert!(!PoolConfig::from_settings(&quic, &off).keep_alive);
        assert!(PoolConfig::from_settings(&plaintext, &on).keep_alive);
    }

    /// The keep-alive cadence must stay comfortably below the negotiated idle
    /// timeout (min of both sides): the 60s default yields the capped 10s
    /// cadence, and the upper bound stays below quinn's client-default 30s
    /// `max_idle_timeout` (a 30s cadence would race the negotiated idle timer
    /// instead of beating it).
    #[test]
    fn keep_alive_interval_derivation() {
        assert_eq!(keep_alive_interval(Duration::from_secs(60)), KEEP_ALIVE_MAX);
        assert_eq!(keep_alive_interval(Duration::from_secs(2)), Duration::from_secs(1));
        assert_eq!(keep_alive_interval(Duration::from_secs(3600)), KEEP_ALIVE_MAX);
        assert_eq!(keep_alive_interval(Duration::from_secs(45)), KEEP_ALIVE_MAX);
        assert!(KEEP_ALIVE_MAX < Duration::from_secs(30), "must stay below quinn's 30s default");
    }
}
