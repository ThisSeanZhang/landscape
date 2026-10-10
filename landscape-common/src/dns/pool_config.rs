use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct UpstreamPoolConfig {
    /// Max persistent stream connections kept per endpoint `(addr, protocol)`.
    pub max_conns_per_endpoint: usize,
    /// Max concurrent requests multiplexed on one stream connection; mirrors
    /// `ResolverOpts::max_active_requests`.
    pub max_inflight_per_conn: usize,
    /// Idle (no in-flight request) stream connection TTL before the reap
    /// closes it.
    pub idle_ttl: Duration,
    /// Max stream connection lifetime, so middlebox state (NAT, firewalls)
    /// cannot go silently stale; retired from handout and closed once
    /// drained.
    pub max_lifetime: Duration,
    /// How long an endpoint is blocked from dialing after a dial failure, so
    /// fast failures cannot turn the acquire loop into a hot redial spin.
    pub dial_failure_cooldown: Duration,
    /// Per-round time allowance; mirrors the legacy `ResolverOpts::timeout`. Racing,
    /// acquisition and dialing all spend from this one allowance.
    pub round_timeout: Duration,
    /// Rounds per lookup; mirrors the legacy `ResolverOpts::attempts`.
    pub attempts: u8,
    /// Endpoints raced per round; mirrors the legacy
    /// `ResolverOpts::num_concurrent_reqs`.
    pub concurrency: usize,
    /// Max CNAME chase depth.
    pub max_cname_depth: u8,
    /// Consecutive query timeouts before a stream connection is retired from
    /// handout.
    pub max_consecutive_timeouts: u8,
}

impl Default for UpstreamPoolConfig {
    fn default() -> Self {
        Self {
            max_conns_per_endpoint: 4,
            max_inflight_per_conn: 16,
            idle_ttl: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(10 * 60),
            dial_failure_cooldown: Duration::from_millis(100),
            round_timeout: Duration::from_secs(1),
            attempts: 3,
            concurrency: 4,
            max_cname_depth: 8,
            max_consecutive_timeouts: 2,
        }
    }
}
