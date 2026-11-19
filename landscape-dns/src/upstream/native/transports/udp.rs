//! Native plaintext-UDP transport.
//!
//! A small per-endpoint pool reuses connected UDP sockets across sequential
//! queries. Each socket is checked out by one query at a time, carries a
//! random DNS id per query, is connected (so the kernel filters foreign
//! sources), and validates the id + question echo before accepting a
//! response. Sockets rotate after a bounded number of uses / lifetime so the
//! source-port exposure stays bounded. The pool retries at the attempt level,
//! so a blackholed upstream is not hammered with datagrams.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Message, Query};
use tokio::net::UdpSocket;

use crate::upstream::native::mark::MarkRuntimeProvider;
use crate::upstream::native::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

use super::{build_message, classify_message};

/// Maximum number of idle sockets kept per endpoint. A home/soft-router
/// workload rarely needs more than this in flight; checked-out sockets are
/// limited by concurrent queries and extras are closed on return instead of
/// growing the cache without bound.
const UDP_SOCKET_POOL_SIZE: usize = 16;
/// Rotate a socket after this many completed exchanges.
const UDP_SOCKET_MAX_REUSES: u32 = 64;
/// Rotate a socket after this age even when it is still under the use cap.
const UDP_SOCKET_MAX_AGE: Duration = Duration::from_secs(30);
/// Scratch buffer used to drain late datagrams before reusing a socket.
const UDP_DRAIN_BUF_SIZE: usize = 4096;

/// Builds UDP connections to one endpoint.
pub(crate) struct UdpConnector {
    pub(super) addr: SocketAddr,
    pub(super) provider: MarkRuntimeProvider,
    pub(super) query_timeout: Duration,
}

impl Debug for UdpConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpConnector").field("addr", &self.addr).finish()
    }
}

#[async_trait]
impl DnsConnector for UdpConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        Ok(Arc::new(UdpConn {
            pool: Arc::new(UdpSocketPool {
                addr: self.addr,
                provider: self.provider.clone(),
                idle: Mutex::new(VecDeque::new()),
            }),
            query_timeout: self.query_timeout,
        }))
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Udp
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    /// Test-only endpoint introspection (topology assertions).
    #[cfg(test)]
    fn test_endpoint(&self) -> Option<(SocketAddr, String)> {
        Some((self.addr, "Udp".to_string()))
    }
}

/// A pooled UDP endpoint. The outer pool treats this object as one logical
/// connection; this inner pool owns the reusable stateless sockets.
struct UdpConn {
    pool: Arc<UdpSocketPool>,
    query_timeout: Duration,
}

impl Debug for UdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpConn").field("addr", &self.pool.addr).finish()
    }
}

struct UdpSocketPool {
    addr: SocketAddr,
    provider: MarkRuntimeProvider,
    idle: Mutex<VecDeque<PooledUdpSocket>>,
}

struct PooledUdpSocket {
    socket: UdpSocket,
    uses: u32,
    created: Instant,
}

impl PooledUdpSocket {
    fn expired(&self) -> bool {
        self.uses >= UDP_SOCKET_MAX_REUSES || self.created.elapsed() >= UDP_SOCKET_MAX_AGE
    }
}

struct UdpLease {
    pool: Arc<UdpSocketPool>,
    entry: Option<PooledUdpSocket>,
}

impl UdpLease {
    fn socket(&self) -> &UdpSocket {
        &self.entry.as_ref().expect("checked-out UDP socket is present until drop").socket
    }
}

impl Drop for UdpLease {
    fn drop(&mut self) {
        let Some(mut entry) = self.entry.take() else { return };
        // A late response from the previous query must never be delivered to
        // the next borrower.
        let mut scratch = [0u8; UDP_DRAIN_BUF_SIZE];
        while entry.socket.try_recv(&mut scratch).is_ok() {}

        entry.uses = entry.uses.saturating_add(1);
        if entry.expired() {
            return;
        }
        let mut idle = self.pool.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < UDP_SOCKET_POOL_SIZE {
            idle.push_back(entry);
        }
    }
}

impl UdpSocketPool {
    async fn checkout(self: &Arc<Self>) -> io::Result<UdpLease> {
        let reused = {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                match idle.pop_front() {
                    Some(entry) if !entry.expired() => break Some(entry),
                    Some(_) => continue,
                    None => break None,
                }
            }
        };
        let entry = match reused {
            Some(entry) => entry,
            None => PooledUdpSocket {
                socket: self.provider.bind_udp(self.addr).await?,
                uses: 0,
                created: Instant::now(),
            },
        };
        Ok(UdpLease { pool: Arc::clone(self), entry: Some(entry) })
    }
}

#[async_trait]
impl DnsConn for UdpConn {
    async fn query(
        &self,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError> {
        let mut message = build_message(query, options);
        // A random id per query: the connected socket filters foreign sources
        // and the id + question echo filter late/forged datagrams.
        message.metadata.id = rand::random();
        let bytes = message.to_vec().map_err(|e| DnsConnError::Internal(e.to_string()))?;

        let lease = self.pool.checkout().await.map_err(|e| DnsConnError::Io(e.to_string()))?;
        let socket = lease.socket();
        socket.send(&bytes).await.map_err(|e| DnsConnError::Io(e.to_string()))?;

        // The receive buffer is the advertised EDNS payload (mirrors hickory:
        // responses larger than the advertised size are truncated and fail to
        // decode, which is the server's protocol violation).
        let mut buf = vec![0u8; usize::from(options.edns_payload_len.max(512))];
        let result = tokio::time::timeout(self.query_timeout, async {
            // Up to three receive attempts (hickory parity): mismatched or
            // undecodable datagrams are dropped, not fatal.
            for _ in 0..3 {
                let len =
                    socket.recv(&mut buf).await.map_err(|e| DnsConnError::Io(e.to_string()))?;
                if let Ok(response) = validate_response(&buf[..len], &message) {
                    return Ok(response);
                }
                // A *decodable* frame that failed validation is spoofed or
                // late — dropped, never trusted. An *undecodable* frame
                // carrying our id and the response bit is a kernel-truncated
                // answer: surface it as a synthesized truncated response so
                // the pool's truncation path (stream retry) recovers the
                // data instead of aging the attempt into a health-counted
                // Timeout.
                if Message::from_vec(&buf[..len]).is_err()
                    && let Some(truncated) = truncated_response(&buf[..len], &message)
                {
                    return Ok(truncated);
                }
            }
            Err(DnsConnError::Timeout)
        })
        .await;

        match result {
            Ok(result) => match result {
                Ok(message) => classify_message(message),
                Err(e) => Err(e),
            },
            Err(_) => Err(DnsConnError::Timeout),
        }
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Udp
    }

    fn ip(&self) -> IpAddr {
        self.pool.addr.ip()
    }

    fn shutdown(&self) {}
}

/// Ignore datagrams that cannot be correlated with this lookup.
fn validate_response(bytes: &[u8], query: &Message) -> Result<Message, ()> {
    let response = Message::from_vec(bytes).map_err(|_| ())?;
    if response.metadata.id != query.metadata.id {
        return Err(());
    }
    super::validate_reply(&response, &query.queries).map_err(|_| ())?;
    Ok(response)
}

/// Detects a kernel-truncated response: a datagram larger than the receive
/// buffer is silently cut by the OS (an EDNS-ignoring server answering
/// beyond the advertised payload size without setting TC), so the message
/// fails to decode — but the 12-octet header survives. If it carries our id
/// and the response (QR) bit, this is our answer losing records, not
/// garbage: synthesize a minimal truncated response (echoed question, TC
/// bit) that flows through the pool's regular truncation handling — the
/// UDP→stream retry recovers the full answer, and the attempt does not age
/// into a `Timeout` that counts against the upstream's health.
fn truncated_response(bytes: &[u8], request: &Message) -> Option<Message> {
    let [b0, b1, b2, ..] = bytes else { return None };
    let id = u16::from_be_bytes([*b0, *b1]);
    // QR bit (0x80 in the flags' high byte) must say "response".
    if id != request.metadata.id || b2 & 0x80 == 0 {
        return None;
    }
    let mut truncated = Message::response(id, request.metadata.op_code);
    truncated.queries.clone_from(&request.queries);
    truncated.metadata.truncation = true;
    Some(truncated)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::op::{DnsRequestOptions, Message, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;

    fn query() -> Message {
        let mut message = build_message(
            &Query::query(Name::from_str("example.com.").unwrap(), RecordType::A),
            &DnsRequestOptions::default(),
        );
        message.metadata.id = 0x1234;
        message
    }

    fn coded_response(code: hickory_proto::op::ResponseCode) -> Message {
        let mut response = Message::response(0x1234, OpCode::Query);
        response.metadata.response_code = code;
        response
    }

    #[tokio::test]
    async fn reuses_idle_udp_socket() {
        let pool = Arc::new(UdpSocketPool {
            addr: SocketAddr::from(([127, 0, 0, 1], 9)),
            provider: MarkRuntimeProvider::new(0, Default::default()),
            idle: Mutex::new(VecDeque::new()),
        });
        let first = pool.checkout().await.unwrap();
        let first_addr = first.socket().local_addr().unwrap();
        drop(first);
        let second = pool.checkout().await.unwrap();
        assert_eq!(second.socket().local_addr().unwrap(), first_addr);
    }

    #[test]
    fn validates_id() {
        let mut wrong_id = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_id.metadata.id = 0x9999;
        assert!(validate_response(&wrong_id.to_vec().unwrap(), &query()).is_err());
    }

    #[test]
    fn validates_question_echo() {
        // A response answering a different question is forged.
        let mut wrong_question = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_question
            .queries
            .push(Query::query(Name::from_str("other.com.").unwrap(), RecordType::A));
        assert!(validate_response(&wrong_question.to_vec().unwrap(), &query()).is_err());

        // The exact echoed question is accepted.
        let mut echoed = coded_response(hickory_proto::op::ResponseCode::NoError);
        echoed.queries.clone_from(&query().queries);
        assert!(validate_response(&echoed.to_vec().unwrap(), &query()).is_ok());
    }

    #[test]
    fn rejects_non_response_messages() {
        assert!(validate_response(&query().to_vec().unwrap(), &query()).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(validate_response(&[0xde, 0xad, 0xbe, 0xef], &query()).is_err());
    }

    /// A full response cut to a header prefix (kernel truncation of an
    /// oversized datagram) is detected and synthesized into a truncated
    /// response carrying the echoed question and the TC bit.
    #[test]
    fn kernel_truncated_response_becomes_tc_fallback() {
        let request = query();
        let mut response = coded_response(hickory_proto::op::ResponseCode::NoError);
        response.queries.clone_from(&request.queries);
        response.answers.push(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        let bytes = response.to_vec().unwrap();
        assert!(Message::from_vec(&bytes).is_ok());

        // Cut mid-question-section: undecodable, but the header (id + QR)
        // survives.
        let cut = &bytes[..20];
        assert!(Message::from_vec(cut).is_err());

        let synthesized = truncated_response(cut, &request).expect("must detect truncation");
        assert!(synthesized.metadata.truncation);
        assert_eq!(synthesized.metadata.id, request.metadata.id);
        assert_eq!(synthesized.queries, request.queries);
    }

    /// Datagrams that do not carry our id, carry the query (not response)
    /// bit, or are too short for a header are never mistaken for
    /// truncations. A header-only datagram with our id and the QR bit is
    /// indistinguishable from a kernel-truncated response and is accepted
    /// as one (it carries no records, so it can only trigger the stream
    /// retry, never inject data).
    #[test]
    fn foreign_or_query_datagrams_are_not_truncation() {
        let request = query();

        // Wrong id.
        let mut wrong_id = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_id.metadata.id = 0x9999;
        let bytes = wrong_id.to_vec().unwrap();
        assert!(truncated_response(&bytes, &request).is_none());

        // Right id, but a query (QR bit clear).
        let bytes = request.to_vec().unwrap();
        assert!(truncated_response(&bytes, &request).is_none());

        // Shorter than a DNS header (id + flags).
        assert!(truncated_response(&[0x12, 0x34], &request).is_none());

        // Header-only with our id and the QR bit: treated as truncated.
        assert!(truncated_response(&[0x12, 0x34, 0x80], &request).is_some());
    }
}
