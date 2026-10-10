use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::{DnsRequest, DnsResponse, Query, ResponseCode};
use hickory_resolver::net::xfer::Protocol;
use hickory_resolver::net::{DnsError, NetError};

use landscape_common::dns::pool_config::UpstreamPoolConfig;

use crate::exp_conn_pool::allowance::TimeAllowance;
use crate::exp_conn_pool::connection::EndpointKey;
use crate::exp_conn_pool::pool::{Lease, StreamConnectionPool};
use crate::exp_conn_pool::transport::WireQuery;

struct Endpoint {
    key: EndpointKey,
    srtt: Srtt,
}

struct Srtt {
    estimate: AtomicU64,
    observations: AtomicU32,
}

const SRTT_FLOOR_MICROS: u64 = 1;
const SRTT_CEILING_MICROS: u64 = 10 * 60 * 1_000_000;

impl Srtt {
    fn new() -> Self {
        // Conservative 10ms seed until a real observation arrives.
        Self {
            estimate: AtomicU64::new(10_000),
            observations: AtomicU32::new(0),
        }
    }

    fn current(&self) -> Duration {
        Duration::from_micros(self.estimate.load(Ordering::Relaxed))
    }

    fn record(&self, rtt: Duration) {
        let prev = self.estimate.load(Ordering::Relaxed) as i64;
        let observed = rtt.as_micros() as i64;
        // EWMA with alpha = 1/8.
        let next = prev + (observed - prev) / 8;
        self.estimate.store(
            next.clamp(SRTT_FLOOR_MICROS as i64, SRTT_CEILING_MICROS as i64) as u64,
            Ordering::Relaxed,
        );
        self.observations.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let prev = self.estimate.load(Ordering::Relaxed);
        let penalty = (prev * 2).saturating_add(10_000).min(SRTT_CEILING_MICROS);
        self.estimate.store(penalty.max(SRTT_FLOOR_MICROS), Ordering::Relaxed);
        self.observations.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct Scheduler {
    pool: Arc<StreamConnectionPool>,
    endpoints: Vec<Endpoint>,
    config: UpstreamPoolConfig,
}

impl Scheduler {
    pub(crate) fn new(
        pool: Arc<StreamConnectionPool>,
        endpoint_keys: Vec<EndpointKey>,
        config: UpstreamPoolConfig,
    ) -> Self {
        // UDP first among unobserved endpoints, mirroring the legacy ordering.
        let mut keys = endpoint_keys;
        keys.sort_by_key(|key| key.protocol != Protocol::Udp);
        Self {
            pool,
            endpoints: keys.into_iter().map(|key| Endpoint { key, srtt: Srtt::new() }).collect(),
            config,
        }
    }

    pub(crate) async fn resolve(&self, request: DnsRequest) -> Result<DnsResponse, NetError> {
        let (message, _options) = request.into_parts();
        let queries: Arc<[Query]> = Arc::from(message.queries.clone());
        let wire = Bytes::from(message.to_vec().map_err(NetError::from)?);

        let mut last_err = NetError::NoConnections;
        for _ in 0..self.config.attempts {
            // Fresh allowance per round, so transient first-packet loss can
            // succeed on retry.
            let allowance = TimeAllowance::new(self.config.round_timeout);
            match self.try_send(wire.clone(), queries.clone(), allowance).await {
                Ok(response) => return Ok(response),
                Err(e) if matches!(e, NetError::Dns(DnsError::NoRecordsFound(_))) => return Err(e),
                Err(e) => last_err = last_err_by_preference(last_err, e),
            }
        }
        Err(last_err)
    }

    async fn try_send(
        &self,
        wire: Bytes,
        queries: Arc<[Query]>,
        allowance: TimeAllowance,
    ) -> Result<DnsResponse, NetError> {
        let mut queue: VecDeque<usize> = (0..self.endpoints.len()).collect();
        self.sort_queue_by_srtt(&mut queue);

        let mut udp_disabled = false;
        let mut backoff = Duration::from_millis(20);
        let mut busy: Vec<usize> = Vec::new();
        let mut err = NetError::NoConnections;

        loop {
            if allowance.is_expired() {
                return Err(NetError::Timeout);
            }

            let mut batch: Vec<usize> = Vec::new();
            while !queue.is_empty() && batch.len() < self.config.concurrency {
                let Some(index) = queue.pop_front() else { break };
                if udp_disabled && self.endpoints[index].key.protocol == Protocol::Udp {
                    continue;
                }
                batch.push(index);
            }

            if batch.is_empty() {
                if !busy.is_empty() && backoff < Duration::from_millis(300) {
                    if allowance.is_expired() {
                        return Err(NetError::Timeout);
                    }
                    let retry_at = std::time::Instant::now() + backoff;
                    tokio::time::sleep_until(tokio::time::Instant::from_std(
                        retry_at.min(allowance.expires_at()),
                    ))
                    .await;
                    queue.extend(busy.drain(..));
                    backoff *= 2;
                    continue;
                }
                return Err(err);
            }

            let mut requests = batch
                .into_iter()
                .map(|index| {
                    let endpoint = &self.endpoints[index];
                    // Mirrors hickory: retransmit at 1.2x the observed SRTT.
                    let query = WireQuery {
                        wire: wire.clone(),
                        retry_interval: endpoint.srtt.current() * 12 / 10,
                        queries: queries.clone(),
                    };
                    let send = self.send_via(endpoint, query, allowance);
                    async move { (index, send.await) }
                })
                .collect::<FuturesUnordered<_>>();

            while let Some((index, result)) = requests.next().await {
                let e = match result {
                    Ok(response) if response.truncation && udp_disabled => NetError::Truncated,
                    Ok(response) if response.truncation => {
                        udp_disabled = true;
                        if let Some(tcp_index) = self.tcp_sibling(index) {
                            queue.push_front(tcp_index);
                        }
                        NetError::Truncated
                    }
                    Ok(response) => return Ok(response),
                    Err(e) => e,
                };
                match &e {
                    NetError::Busy => busy.push(index),
                    NetError::Io(_)
                    | NetError::NoConnections
                    | NetError::Timeout
                    | NetError::Truncated => {}
                    // Authoritative answers (NXDOMAIN, NODATA, SERVFAIL, ...)
                    // are final.
                    _ => return Err(e),
                }
                err = last_err_by_preference(err, e);
            }
        }
    }

    fn sort_queue_by_srtt(&self, queue: &mut VecDeque<usize>) {
        let mut indices = queue.drain(..).collect::<Vec<_>>();
        indices.sort_by_key(|&index| self.endpoints[index].srtt.current());
        queue.extend(indices);
    }

    async fn send_via(
        &self,
        endpoint: &Endpoint,
        query: WireQuery,
        allowance: TimeAllowance,
    ) -> Result<DnsResponse, NetError> {
        let lease = self.pool.acquire(endpoint.key, allowance).await?;
        let was_reused = lease.has_been_used();

        let (result, rtt) = match allowance.complete_within(send_once(&lease, query.clone())).await {
            Ok((result, rtt)) => (result, rtt),
            Err(timeout) => {
                lease.record_query_timeout();
                (Err(timeout), Duration::ZERO)
            }
        };
        // A reused connection closed by the peer is not the server's fault:
        // redial once (queries are idempotent).
        if was_reused
            && let Err(e) = &result
            && e.is_connection_closed()
        {
            tracing::debug!(endpoint = ?endpoint.key, "pooled connection closed by peer, redialing once");
            let fresh = self.pool.acquire(endpoint.key, allowance).await?;
            let (result, rtt) = match allowance.complete_within(send_once(&fresh, query)).await {
                Ok((result, rtt)) => (result, rtt),
                Err(timeout) => {
                    fresh.record_query_timeout();
                    (Err(timeout), Duration::ZERO)
                }
            };
            record_srtt(&endpoint.srtt, &result, rtt);
            return result;
        }

        record_srtt(&endpoint.srtt, &result, rtt);
        result
    }

    fn tcp_sibling(&self, index: usize) -> Option<usize> {
        let addr = self.endpoints[index].key.addr;
        self.endpoints.iter().position(|endpoint| {
            endpoint.key.addr == addr && endpoint.key.protocol == Protocol::Tcp
        })
    }

    pub(crate) fn live_connection_counts(&self) -> Vec<(EndpointKey, usize)> {
        self.pool.live_connection_counts()
    }

    #[cfg(test)]
    pub(crate) fn sweep_idle(&self) {
        self.pool.reap_all();
    }

    #[cfg(test)]
    pub(crate) fn srtt_snapshot(&self) -> Vec<SrttSample> {
        self.endpoints
            .iter()
            .map(|endpoint| SrttSample {
                endpoint: endpoint.key,
                srtt: endpoint.srtt.current(),
                observations: endpoint.srtt.observations.load(Ordering::Relaxed),
            })
            .collect()
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct SrttSample {
    pub(crate) endpoint: EndpointKey,
    pub(crate) srtt: Duration,
    pub(crate) observations: u32,
}

async fn send_once(lease: &Lease, query: WireQuery) -> (Result<DnsResponse, NetError>, Duration) {
    let start = Instant::now();
    let response = lease.query(query).await;
    let rtt = start.elapsed();
    let result = match response {
        // Truncated responses go back untouched: the scheduler decides the
        // TCP fallback.
        Ok(response) if response.truncation => Ok(response),
        Ok(response) => match DnsError::from_response(response) {
            Ok(response) => Ok(response),
            Err(e) => Err(NetError::from(e)),
        },
        Err(e) => Err(e),
    };
    (result, rtt)
}

fn record_srtt(srtt: &Srtt, result: &Result<DnsResponse, NetError>, rtt: Duration) {
    match result {
        Ok(_) => srtt.record(rtt),
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records)))
            if no_records.response_code == ResponseCode::ServFail =>
        {
            srtt.record(rtt);
        }
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) => srtt.record_failure(),
        Err(NetError::Busy) => {}
        Err(_) => srtt.record_failure(),
    }
}

fn last_err_by_preference(previous: NetError, current: NetError) -> NetError {
    match (&previous, &current) {
        (NetError::Dns(DnsError::NoRecordsFound(_)), _) => previous,
        (_, NetError::Dns(DnsError::NoRecordsFound(_))) => current,
        _ => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srtt_ewma_and_failure_penalty() {
        let srtt = Srtt::new();
        assert_eq!(srtt.current(), Duration::from_micros(10_000));

        srtt.record(Duration::from_millis(90));
        // 10_000 + (90_000 - 10_000)/8 = 20_000
        assert_eq!(srtt.current(), Duration::from_micros(20_000));

        srtt.record_failure();
        // 20_000 * 2 + 10_000 = 50_000
        assert_eq!(srtt.current(), Duration::from_micros(50_000));
    }

    #[test]
    fn last_err_prefers_dns_answers() {
        let dns = NetError::Dns(DnsError::NoRecordsFound(hickory_resolver::net::NoRecords::new(
            Box::new(hickory_proto::op::Query::default()),
            ResponseCode::NXDomain,
        )));
        assert!(matches!(
            last_err_by_preference(NetError::Timeout, dns.clone()),
            NetError::Dns(DnsError::NoRecordsFound(_))
        ));
        assert!(matches!(
            last_err_by_preference(dns, NetError::Timeout),
            NetError::Dns(DnsError::NoRecordsFound(_))
        ));
    }
}
