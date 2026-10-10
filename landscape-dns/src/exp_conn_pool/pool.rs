use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::DnsResponse;
use hickory_resolver::PoolContext;
use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};
use hickory_resolver::net::NetError;
use hickory_resolver::net::xfer::Protocol;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use landscape_common::dns::pool_config::UpstreamPoolConfig;

use crate::exp_conn_pool::allowance::TimeAllowance;
use crate::exp_conn_pool::connection::{EndpointKey, InflightGuard, PooledConnection};
use crate::exp_conn_pool::transport::{
    DialParams, Transport, UdpExchange, WireQuery, connect_tcp, connect_tls, dot_client_config,
};

const REAP_EVERY: u64 = 64;

const TRANSIENT_RETRY: Duration = Duration::from_millis(1);

pub(crate) struct StreamConnectionPool {
    state: Arc<PoolState>,
    dial: DialParams,
    tls: Arc<ClientConfig>,
    configs: HashMap<EndpointKey, ConnectionConfig>,
    config: UpstreamPoolConfig,
    next_id: AtomicU64,
    acquires: AtomicU64,
}

struct PoolState {
    endpoints: HashMap<EndpointKey, Arc<EndpointPool>>,
    write: Mutex<()>,
}

struct EndpointPool {
    snapshot: ArcSwap<ConnsSnapshot>,
    conn_permits: Arc<Semaphore>,
    inflight_permits: Option<Arc<Semaphore>>,
}

#[derive(Clone, Default)]
struct ConnsSnapshot {
    conns: Vec<Arc<PooledConnection>>,
    cooldown_until: Option<Instant>,
}

impl ConnsSnapshot {
    fn active_cooldown(&self, now: Instant) -> Option<Instant> {
        self.cooldown_until.filter(|expiry| *expiry > now)
    }
}

impl EndpointPool {
    fn new(conn_capacity: usize, inflight_capacity: Option<usize>) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(ConnsSnapshot::default()),
            conn_permits: Arc::new(Semaphore::new(conn_capacity)),
            inflight_permits: inflight_capacity.map(|n| Arc::new(Semaphore::new(n))),
        }
    }
}

impl StreamConnectionPool {
    pub(crate) fn new(
        dial: DialParams,
        cx: Arc<PoolContext>,
        configs: HashMap<EndpointKey, ConnectionConfig>,
        config: UpstreamPoolConfig,
    ) -> Self {
        let endpoints: HashMap<EndpointKey, Arc<EndpointPool>> = configs
            .keys()
            .map(|key| {
                let ep = if key.protocol.is_datagram() {
                    EndpointPool::new(1, None)
                } else {
                    let conns = config.max_conns_per_endpoint.max(1);
                    let inflight = conns.saturating_mul(config.max_inflight_per_conn.max(1));
                    EndpointPool::new(conns, Some(inflight))
                };
                (*key, Arc::new(ep))
            })
            .collect();
        let state = Arc::new(PoolState { endpoints, write: Mutex::new(()) });
        Self {
            state,
            dial,
            tls: dot_client_config(cx.tls.clone()),
            configs,
            config,
            next_id: AtomicU64::new(0),
            acquires: AtomicU64::new(0),
        }
    }

    pub(crate) async fn acquire(
        &self,
        endpoint: EndpointKey,
        allowance: TimeAllowance,
    ) -> Result<Lease, NetError> {
        let Some(ep) = self.state.endpoints.get(&endpoint) else {
            return Err(NetError::NoConnections);
        };
        let Some(config) = self.configs.get(&endpoint) else {
            return Err(NetError::NoConnections);
        };

        self.maybe_reap(endpoint);

        let inflight = match &ep.inflight_permits {
            Some(sem) => Some(self.acquire_inflight(sem, allowance).await?),
            None => None,
        };

        loop {
            if let Some(conn) = self.pick_available(ep, endpoint.protocol) {
                return Ok(Lease::new(conn, inflight));
            }

            if ep.snapshot.load().active_cooldown(Instant::now()).is_none() {
                match ep.conn_permits.clone().try_acquire_owned() {
                    Ok(conn_permit) => {
                        return match self.dial(endpoint, config, allowance).await {
                            Ok(transport) => {
                                let conn = self.insert_dialed(endpoint, transport, conn_permit);
                                Ok(Lease::new(conn, inflight))
                            }
                            Err(e) => {
                                self.record_dial_failure(endpoint);
                                Err(e)
                            }
                        };
                    }
                    Err(TryAcquireError::NoPermits) => {}
                    Err(TryAcquireError::Closed) => return Err(NetError::NoConnections),
                }
            }

            if allowance.is_expired() {
                return Err(NetError::Timeout);
            }
            // Wait for the cooldown to lift, a connection to be reaped, or a
            // dial to finish. The in-flight semaphore is the real queue; this
            // pause only covers connection-slot transients.
            match ep.snapshot.load().active_cooldown(Instant::now()) {
                Some(cooldown) => {
                    let wake_at = cooldown.min(allowance.expires_at());
                    tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at)).await;
                }
                None => {
                    self.reap(endpoint);
                    let pause = TRANSIENT_RETRY.min(allowance.time_left().unwrap_or_default());
                    tokio::time::sleep(pause).await;
                }
            }
        }
    }

    async fn acquire_inflight(
        &self,
        sem: &Arc<Semaphore>,
        allowance: TimeAllowance,
    ) -> Result<OwnedSemaphorePermit, NetError> {
        match tokio::time::timeout_at(
            tokio::time::Instant::from_std(allowance.expires_at()),
            sem.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(NetError::NoConnections),
            Err(_elapsed) => Err(NetError::Timeout),
        }
    }

    fn pick_available(
        &self,
        ep: &EndpointPool,
        protocol: Protocol,
    ) -> Option<Arc<PooledConnection>> {
        let snap = ep.snapshot.load();
        if protocol.is_datagram() {
            return snap.conns.iter().find(|conn| conn.is_usable()).cloned();
        }
        snap.conns
            .iter()
            .filter(|conn| conn.is_usable() && conn.inflight() < self.config.max_inflight_per_conn)
            .min_by_key(|conn| conn.inflight())
            .cloned()
    }

    fn insert_dialed(
        &self,
        endpoint: EndpointKey,
        transport: Transport,
        conn_permit: OwnedSemaphorePermit,
    ) -> Arc<PooledConnection> {
        let ep = self.state.endpoints.get(&endpoint).expect("acquire checked the endpoint");
        let _write = self.state.write.lock().unwrap_or_else(|e| e.into_inner());
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let conn = Arc::new(PooledConnection::new(
            id,
            endpoint,
            transport,
            conn_permit,
            self.config.max_consecutive_timeouts,
        ));
        let snap = ep.snapshot.load();
        let mut next = (*snap).as_ref().clone();
        next.cooldown_until = None;
        next.conns.retain(|existing| existing.is_usable());
        next.conns.push(conn.clone());
        ep.snapshot.store(Arc::new(next));
        tracing::debug!(?endpoint, conn_id = conn.id(), "pooled upstream connection established");
        conn
    }

    fn record_dial_failure(&self, endpoint: EndpointKey) {
        let Some(ep) = self.state.endpoints.get(&endpoint) else { return };
        let _write = self.state.write.lock().unwrap_or_else(|e| e.into_inner());
        let snap = ep.snapshot.load();
        let mut next = (*snap).as_ref().clone();
        let now = Instant::now();
        // On overflow the cooldown is already far in the future; `now` is the
        // harmless fallback.
        next.cooldown_until =
            Some(now.checked_add(self.config.dial_failure_cooldown).unwrap_or(now));
        ep.snapshot.store(Arc::new(next));
    }

    async fn dial(
        &self,
        endpoint: EndpointKey,
        config: &ConnectionConfig,
        allowance: TimeAllowance,
    ) -> Result<Transport, NetError> {
        match endpoint.protocol {
            Protocol::Tcp => {
                connect_tcp(endpoint.addr, self.dial, allowance).await.map(Transport::Tcp)
            }
            Protocol::Tls => {
                let ProtocolConfig::Tls { server_name } = &config.protocol else {
                    return Err(NetError::from("TLS endpoint without a server name"));
                };
                let server_name = ServerName::try_from(server_name.to_string())
                    .map_err(|_| NetError::from("invalid TLS server name"))?;
                connect_tls(endpoint.addr, server_name, self.tls.clone(), self.dial, allowance)
                    .await
                    .map(Transport::Tls)
            }
            Protocol::Udp => Ok(Transport::Udp(UdpExchange::new(endpoint.addr, self.dial))),
            // Exhaustiveness arm: `endpoint_configs` produces only Tcp, Udp and Tls.
            _ => Err(NetError::from("protocol not supported by the pooled engine")),
        }
    }

    pub(crate) fn live_connection_counts(&self) -> Vec<(EndpointKey, usize)> {
        let mut out: Vec<(EndpointKey, usize)> = self
            .state
            .endpoints
            .iter()
            .map(|(endpoint, ep)| {
                let snap = ep.snapshot.load();
                (*endpoint, snap.conns.iter().filter(|conn| conn.is_usable()).count())
            })
            .collect();
        out.sort_by_key(|(endpoint, _)| (endpoint.addr, endpoint.protocol.as_str()));
        out
    }

    fn maybe_reap(&self, endpoint: EndpointKey) {
        if !self.acquires.fetch_add(1, Ordering::Relaxed).is_multiple_of(REAP_EVERY) {
            return;
        }
        self.reap(endpoint);
    }

    fn reap(&self, endpoint: EndpointKey) {
        let Some(ep) = self.state.endpoints.get(&endpoint) else { return };
        let write = self.state.write.lock().unwrap_or_else(|e| e.into_inner());
        reap_snapshot(ep, endpoint.protocol, &self.config);
        drop(write);
    }

    #[cfg(test)]
    pub(crate) fn reap_all(&self) {
        let write = self.state.write.lock().unwrap_or_else(|e| e.into_inner());
        for (endpoint, ep) in &self.state.endpoints {
            reap_snapshot(ep, endpoint.protocol, &self.config);
        }
        drop(write);
    }
}

pub(crate) struct Lease {
    conn: Arc<PooledConnection>,
    _conn_inflight: InflightGuard,
    _endpoint_inflight: Option<OwnedSemaphorePermit>,
}

impl Lease {
    fn new(conn: Arc<PooledConnection>, endpoint_inflight: Option<OwnedSemaphorePermit>) -> Self {
        let guard = conn.enter_inflight();
        Self {
            conn,
            _conn_inflight: guard,
            _endpoint_inflight: endpoint_inflight,
        }
    }

    pub(crate) fn has_been_used(&self) -> bool {
        self.conn.has_been_used()
    }

    pub(crate) fn record_query_timeout(&self) {
        self.conn.record_query_timeout();
    }

    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        self.conn.query(query).await
    }
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease").field("conn", &self.conn).finish()
    }
}

fn reap_snapshot(ep: &EndpointPool, protocol: Protocol, config: &UpstreamPoolConfig) -> bool {
    let now = Instant::now();
    let snap = ep.snapshot.load();
    if protocol.is_datagram() {
        if snap.conns.iter().any(|conn| !conn.is_usable()) {
            let mut next = (*snap).as_ref().clone();
            next.conns.retain(|conn| conn.is_usable());
            ep.snapshot.store(Arc::new(next));
        }
        return false;
    }
    let mut next = (*snap).as_ref().clone();
    let mut removed = false;
    next.conns.retain(|conn| {
        if conn.age(now) >= config.max_lifetime {
            conn.retire();
        }
        let remove = conn.is_dead()
            || (conn.inflight() == 0 && conn.idle_for(now) >= config.idle_ttl)
            || (conn.is_retired() && conn.inflight() == 0);
        if remove {
            // Prompt teardown; in-flight requests keep their own references
            // and finish undisturbed.
            conn.close();
            removed = true;
        }
        !remove
    });
    if removed {
        ep.snapshot.store(Arc::new(next));
    }
    removed
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use hickory_resolver::config::{ConnectionConfig, ProtocolConfig, ResolverOpts};
    use hickory_resolver::net::xfer::Protocol;
    use hickory_resolver::{PoolContext, TlsConfig};

    use landscape_common::dns::pool_config::UpstreamPoolConfig;

    use super::StreamConnectionPool;
    use crate::exp_conn_pool::allowance::TimeAllowance;
    use crate::exp_conn_pool::connection::EndpointKey;
    use crate::exp_conn_pool::transport::DialParams;

    fn pool_at(
        addr: SocketAddr,
        protocol: Protocol,
        protocol_config: ProtocolConfig,
        config: UpstreamPoolConfig,
    ) -> (StreamConnectionPool, EndpointKey) {
        let dial = DialParams { mark_value: 0, bind_addr4: None, bind_addr6: None };
        let cx = Arc::new(PoolContext::new(ResolverOpts::default(), TlsConfig::new().unwrap()));
        let key = EndpointKey { addr, protocol };
        let mut conn = ConnectionConfig::new(protocol_config);
        conn.port = addr.port();
        let mut configs = HashMap::new();
        configs.insert(key, conn);
        (StreamConnectionPool::new(dial, cx, configs, config), key)
    }

    fn pool_with(
        protocol: Protocol,
        protocol_config: ProtocolConfig,
        config: UpstreamPoolConfig,
    ) -> (StreamConnectionPool, EndpointKey) {
        pool_at(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            protocol,
            protocol_config,
            config,
        )
    }

    fn udp_pool(cooldown: Duration) -> (StreamConnectionPool, EndpointKey) {
        let config = UpstreamPoolConfig {
            dial_failure_cooldown: cooldown,
            ..UpstreamPoolConfig::default()
        };
        pool_with(Protocol::Udp, ProtocolConfig::Udp, config)
    }

    #[tokio::test]
    async fn dial_failure_cooldown_arms_then_lifts() {
        let (pool, key) = udp_pool(Duration::from_millis(50));

        pool.record_dial_failure(key);
        assert!(
            pool.state
                .endpoints
                .get(&key)
                .unwrap()
                .snapshot
                .load()
                .active_cooldown(Instant::now())
                .is_some(),
            "a failed dial must arm the endpoint cooldown"
        );

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            pool.state
                .endpoints
                .get(&key)
                .unwrap()
                .snapshot
                .load()
                .active_cooldown(Instant::now())
                .is_none(),
            "cooldown expiry must re-allow dialing"
        );
    }

    #[tokio::test]
    async fn stream_conn_slots_are_bounded_by_capacity() {
        let (pool, key) = pool_with(
            Protocol::Tcp,
            ProtocolConfig::Tcp,
            UpstreamPoolConfig {
                max_conns_per_endpoint: 4,
                ..UpstreamPoolConfig::default()
            },
        );
        let ep = pool.state.endpoints.get(&key).unwrap();
        assert_eq!(ep.conn_permits.available_permits(), 4);

        let mut held = Vec::new();
        for i in 0..4 {
            held.push(ep.conn_permits.clone().try_acquire_owned().expect("slot within capacity"));
            assert_eq!(ep.conn_permits.available_permits(), 4 - i - 1);
        }
        assert!(
            ep.conn_permits.clone().try_acquire_owned().is_err(),
            "a fifth connection slot must be refused"
        );

        held.pop();
        assert_eq!(ep.conn_permits.available_permits(), 1, "a freed slot opens capacity again");
    }

    #[tokio::test]
    async fn datagram_holds_one_conn_slot_and_no_inflight_bound() {
        let (pool, key) = udp_pool(Duration::from_secs(5));
        let ep = pool.state.endpoints.get(&key).unwrap();
        assert_eq!(ep.conn_permits.available_permits(), 1, "datagram dials one handle");
        assert!(ep.inflight_permits.is_none(), "datagram exchanges are not capacity-bounded");
    }

    #[tokio::test]
    async fn stream_inflight_permits_bound_total_inflight() {
        let (pool, key) = pool_with(
            Protocol::Tcp,
            ProtocolConfig::Tcp,
            UpstreamPoolConfig {
                max_conns_per_endpoint: 2,
                max_inflight_per_conn: 4,
                ..UpstreamPoolConfig::default()
            },
        );
        let ep = pool.state.endpoints.get(&key).unwrap();
        let inflight = ep.inflight_permits.as_ref().unwrap();
        assert_eq!(
            inflight.available_permits(),
            8,
            "total in-flight capacity is conns × per-conn inflight"
        );
    }

    #[tokio::test]
    async fn acquire_cancelled_mid_dial_releases_capacity() {
        // A silent local listener: the TCP handshake completes in the
        // kernel, but a TLS ClientHello never gets a ServerHello, so
        // `acquire` parks inside `dial` until cancelled.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = silent.local_addr().expect("read bound address");

        let config = UpstreamPoolConfig {
            max_conns_per_endpoint: 1,
            ..UpstreamPoolConfig::default()
        };
        let (pool, key) = pool_at(
            addr,
            Protocol::Tls,
            ProtocolConfig::Tls { server_name: Arc::from("localhost") },
            config,
        );
        let pool = Arc::new(pool);

        let dialer = pool.clone();
        let allowance = TimeAllowance::new(Duration::from_secs(30));
        let task = tokio::spawn(async move {
            let _ = dialer.acquire(key, allowance).await;
        });

        // Wait until the in-flight dial holds the only connection slot.
        let ep = pool.state.endpoints.get(&key).unwrap();
        let mut reserved = false;
        for _ in 0..400 {
            if ep.conn_permits.available_permits() == 0 {
                reserved = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(reserved, "the spawned acquire must hold the connection slot");

        task.abort();
        let _ = task.await;
        assert_eq!(
            ep.conn_permits.available_permits(),
            1,
            "a cancelled dial must release its connection slot"
        );

        drop(silent);
    }
}
