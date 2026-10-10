use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::ProtoError;
use hickory_proto::op::DnsResponse;
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::Protocol;
use tokio::sync::OwnedSemaphorePermit;

use crate::exp_conn_pool::transport::{Transport, WireQuery};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EndpointKey {
    pub addr: SocketAddr,
    pub protocol: Protocol,
}

struct ConnState {
    id: u64,
    endpoint: EndpointKey,
    inflight: AtomicUsize,
    uses: AtomicU32,
    dead: AtomicBool,
    retired: AtomicBool,
    timeout_streak: AtomicU8,
    max_consecutive_timeouts: u8,
    last_used_ms: AtomicU64,
    created_at: Instant,
}

fn pool_epoch() -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_ms() -> u64 {
    pool_epoch().elapsed().as_millis() as u64
}

impl ConnState {
    fn new(id: u64, endpoint: EndpointKey, max_consecutive_timeouts: u8) -> Self {
        let now = Instant::now();
        Self {
            id,
            endpoint,
            inflight: AtomicUsize::new(0),
            uses: AtomicU32::new(0),
            dead: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            timeout_streak: AtomicU8::new(0),
            max_consecutive_timeouts,
            // Born "just used": a fresh connection must not look
            // idle-since-epoch and be reaped before its first query.
            last_used_ms: AtomicU64::new(now_ms()),
            created_at: now,
        }
    }

    fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    fn record_error(&self, error: &NetError) {
        // Datagram exchanges are stateless per query and never fail as connections.
        if self.endpoint.protocol.is_datagram() {
            return;
        }
        match error {
            NetError::Dns(_) => {}
            NetError::Proto(ProtoError::Msg(_))
            | NetError::Msg(_)
            | NetError::Message(_)
            | NetError::RequestTooLarge => {}
            NetError::Timeout => self.record_query_timeout(),
            // `Busy` cannot be genuine saturation (the pool caps in-flight
            // below the mux limits), so it means the exchange task exited:
            // dead.
            _ => self.dead.store(true, Ordering::Release),
        }
    }

    fn record_query_timeout(&self) {
        let streak = self.timeout_streak.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        if streak >= self.max_consecutive_timeouts {
            self.retired.store(true, Ordering::Release);
        }
    }

    fn record_success(&self) {
        self.timeout_streak.store(0, Ordering::Release);
    }

    fn touch(&self) {
        self.last_used_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn idle_for(&self, now: Instant) -> std::time::Duration {
        let now_ms = (now - pool_epoch()).as_millis() as u64;
        Duration::from_millis(now_ms.saturating_sub(self.last_used_ms.load(Ordering::Relaxed)))
    }

    fn age(&self, now: Instant) -> std::time::Duration {
        now.saturating_duration_since(self.created_at)
    }
}

pub(crate) struct PooledConnection {
    transport: Transport,
    state: Arc<ConnState>,
    _conn_permit: OwnedSemaphorePermit,
}

impl PooledConnection {
    pub(crate) fn new(
        id: u64,
        endpoint: EndpointKey,
        transport: Transport,
        conn_permit: OwnedSemaphorePermit,
        max_consecutive_timeouts: u8,
    ) -> Self {
        Self {
            transport,
            state: Arc::new(ConnState::new(id, endpoint, max_consecutive_timeouts)),
            _conn_permit: conn_permit,
        }
    }

    pub(crate) fn record_query_timeout(&self) {
        if !self.state.endpoint.protocol.is_datagram() {
            self.state.record_query_timeout();
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.state.id
    }

    pub(crate) fn inflight(&self) -> usize {
        self.state.inflight()
    }

    pub(crate) fn is_usable(&self) -> bool {
        !self.state.is_dead() && !self.state.is_retired() && self.transport.is_alive()
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.state.is_dead() || !self.transport.is_alive()
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.state.is_retired()
    }

    pub(crate) fn retire(&self) {
        self.state.retired.store(true, Ordering::Release);
    }

    pub(crate) fn close(&self) {
        self.transport.close();
    }

    pub(crate) fn idle_for(&self, now: Instant) -> std::time::Duration {
        self.state.idle_for(now)
    }

    pub(crate) fn age(&self, now: Instant) -> std::time::Duration {
        self.state.age(now)
    }

    pub(crate) fn has_been_used(&self) -> bool {
        self.state.uses.load(Ordering::Acquire) > 0
    }

    pub(crate) fn enter_inflight(self: &Arc<Self>) -> InflightGuard {
        self.state.inflight.fetch_add(1, Ordering::AcqRel);
        self.state.touch();
        InflightGuard { state: self.state.clone() }
    }

    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        self.state.uses.fetch_add(1, Ordering::AcqRel);
        self.state.touch();

        let result = self.transport.query(query).await;
        match &result {
            Ok(_) => {
                self.state.touch();
                self.state.record_success();
            }
            Err(error) => self.state.record_error(error),
        }
        result
    }
}

pub(crate) struct InflightGuard {
    state: Arc<ConnState>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.state.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl std::fmt::Debug for PooledConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledConnection")
            .field("id", &self.state.id)
            .field("endpoint", &self.state.endpoint)
            .field("inflight", &self.state.inflight())
            .field("dead", &self.state.is_dead())
            .field("retired", &self.state.is_retired())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn tcp_endpoint() -> EndpointKey {
        EndpointKey {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn fresh_connection_is_born_used() {
        let _ = now_ms();
        std::thread::sleep(Duration::from_millis(10));

        let state = ConnState::new(0, tcp_endpoint(), 2);

        assert!(
            state.idle_for(Instant::now()) < Duration::from_millis(5),
            "a freshly created connection must not count as idle"
        );
    }
}
