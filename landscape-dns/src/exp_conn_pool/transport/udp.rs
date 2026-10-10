//! Self-managed DNS-over-UDP: each query borrows a marked socket from a
//! small per-endpoint pool, rotated so source ports vary (a spoofing
//! defense). A socket retires after [`UDP_SOCKET_MAX_REUSES`] exchanges or
//! [`UDP_SOCKET_MAX_AGE`], whichever first. Responses are accepted only when
//! the ID and question section match the pending request (RFC 1035 §7.3).
//! Retransmission resends at the request's retry interval, floored at
//! [`MIN_RETRY_INTERVAL`]; the retransmit deadline is fixed per window, so
//! junk cannot postpone it.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use hickory_proto::op::DnsResponse;
use hickory_resolver::net::NetError;

use crate::connection::provider::set_socket_mark;
use crate::exp_conn_pool::transport::{DialParams, WireQuery};

const MAX_DATAGRAM: usize = 4096;

const MIN_RETRY_INTERVAL: Duration = Duration::from_millis(10);

const UDP_SOCKET_POOL_SIZE: usize = 16;

const UDP_SOCKET_MAX_REUSES: u32 = 64;

const UDP_SOCKET_MAX_AGE: Duration = Duration::from_secs(30);

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

struct UdpSocketPool {
    peer: SocketAddr,
    dial: DialParams,
    idle: Mutex<VecDeque<PooledUdpSocket>>,
}

impl UdpSocketPool {
    fn create_socket(&self) -> Result<PooledUdpSocket, NetError> {
        let socket = std::net::UdpSocket::bind(self.dial.udp_bind_addr(self.peer))
            .map_err(NetError::from)?;
        socket.set_nonblocking(true).map_err(NetError::from)?;
        set_socket_mark(socket.as_raw_fd(), self.dial.mark_value).map_err(NetError::from)?;
        socket.connect(self.peer).map_err(NetError::from)?;
        Ok(PooledUdpSocket {
            socket: UdpSocket::from_std(socket).map_err(NetError::from)?,
            uses: 0,
            created: Instant::now(),
        })
    }

    fn checkout(self: &Arc<Self>) -> Result<CheckedOutUdp, NetError> {
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
            None => self.create_socket()?,
        };
        Ok(CheckedOutUdp { pool: Arc::clone(self), entry: Some(entry) })
    }

    fn put(&self, mut entry: PooledUdpSocket) {
        entry.uses = entry.uses.saturating_add(1);
        if entry.expired() {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < UDP_SOCKET_POOL_SIZE {
            idle.push_back(entry);
        }
    }
}

struct CheckedOutUdp {
    pool: Arc<UdpSocketPool>,
    entry: Option<PooledUdpSocket>,
}

impl CheckedOutUdp {
    fn socket(&self) -> &UdpSocket {
        &self.entry.as_ref().expect("checked-out socket is present until drop").socket
    }
}

impl Drop for CheckedOutUdp {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            // Drain queued leftovers so the next borrower does not read a
            // stale datagram.
            let mut scratch = [0u8; MAX_DATAGRAM];
            while entry.socket.try_recv(&mut scratch).is_ok() {}
            self.pool.put(entry);
        }
    }
}

pub(crate) struct UdpExchange {
    pool: Arc<UdpSocketPool>,
}

impl UdpExchange {
    pub(crate) fn new(peer: SocketAddr, dial: DialParams) -> Self {
        let pool = Arc::new(UdpSocketPool { peer, dial, idle: Mutex::new(VecDeque::new()) });
        // Warm the pool so queries rotate source ports from the start;
        // failures are non-fatal (checkout binds on demand).
        let mut warm = VecDeque::with_capacity(UDP_SOCKET_POOL_SIZE);
        for _ in 0..UDP_SOCKET_POOL_SIZE {
            match pool.create_socket() {
                Ok(socket) => warm.push_back(socket),
                Err(_) => break,
            }
        }
        *pool.idle.lock().unwrap_or_else(|e| e.into_inner()) = warm;
        Self { pool }
    }
}

impl UdpExchange {
    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        let pool = Arc::clone(&self.pool);
        let id = query.id();
        let payload = query.wire;
        let questions = query.queries;
        let peer = pool.peer;
        // Sub-floor intervals would flood a blackholed peer.
        let retry_interval = query.retry_interval.max(MIN_RETRY_INTERVAL);

        let checked = pool.checkout()?;
        let socket = checked.socket();
        let mut buf = vec![0u8; MAX_DATAGRAM];

        loop {
            socket.send(&payload).await.map_err(NetError::from)?;
            // Fixed retransmit deadline: junk mid-window must not postpone
            // the retransmit.
            let retry_at = tokio::time::Instant::now() + retry_interval;
            'wait: loop {
                tokio::select! {
                    received = socket.recv(&mut buf) => {
                        let len = received.map_err(NetError::from)?;
                        let response = match DnsResponse::from_buffer(buf[..len].to_vec()) {
                            Ok(response) => response,
                            Err(_) => continue 'wait,
                        };
                        // The connected socket pinned the source; the ID is
                        // the remaining check. Mismatches keep waiting, not
                        // retransmitting.
                        if response.metadata.id != id {
                            continue 'wait;
                        }
                        // RFC 1035 §7.3: the question section must also match;
                        // mismatches are treated like spoofs.
                        let question_matches = questions.len() == response.queries.len()
                            && response.queries.iter().all(|q| questions.contains(q));
                        if !question_matches {
                            tracing::warn!(%peer, "detected forged question section, ignoring response");
                            continue 'wait;
                        }
                        return Ok(response);
                    }
                    _ = tokio::time::sleep_until(retry_at) => {
                        break 'wait;
                    }
                }
            }
        }
    }

    pub(crate) fn is_alive(&self) -> bool {
        true
    }

    pub(crate) fn close(&self) {}
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::net::UdpSocket;

    use crate::exp_conn_pool::transport::wire_query;

    fn localhost_dial() -> super::DialParams {
        super::DialParams { mark_value: 0, bind_addr4: None, bind_addr6: None }
    }

    fn query(name: &str) -> DnsRequest {
        let query = Query::query(Name::parse(name, None).unwrap(), RecordType::A);
        DnsRequest::from_query(query, DnsRequestOptions::default())
    }

    async fn spawn_echo_upstream() -> std::net::SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else { break };
                let Ok(mut message) = Message::from_vec(&buf[..len]) else { continue };
                message.metadata.message_type = MessageType::Response;
                let response = message.to_vec().unwrap();
                let _ = socket.send_to(&response, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn round_trip_and_id_match() {
        let peer = spawn_echo_upstream().await;
        let exchange = super::UdpExchange::new(peer, localhost_dial());
        assert!(exchange.is_alive());

        let request = query("example.com.");
        let id = request.metadata.id;
        let response = exchange.query(wire_query(request)).await.unwrap();
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
    }

    #[tokio::test]
    async fn mismatches_and_garbage_are_ignored() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, client) = socket.recv_from(&mut buf).await.unwrap();
            let mut message = Message::from_vec(&buf[..len]).unwrap();
            let id = message.metadata.id;
            message.metadata.message_type = MessageType::Response;

            let mut wrong = message.clone();
            wrong.metadata.id = id ^ 0x00ff;
            let _ = socket.send_to(&wrong.to_vec().unwrap(), client).await;

            let _ = socket.send_to(&[0xff, 0xfe, 0xfd], client).await;

            let _ = socket.send_to(&message.to_vec().unwrap(), client).await;
        });

        let exchange = super::UdpExchange::new(peer, localhost_dial());
        let request = query("example.com.");
        let id = request.metadata.id;
        let response = exchange.query(wire_query(request)).await.unwrap();
        assert_eq!(response.metadata.id, id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn forged_question_response_is_ignored() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, client) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();

            let mut forged = Message::response(request.metadata.id, request.op_code);
            forged.queries =
                vec![Query::query(Name::parse("evil.example.", None).unwrap(), RecordType::A)];
            let _ = socket.send_to(&forged.to_vec().unwrap(), client).await;

            let mut legit = Message::response(request.metadata.id, request.op_code);
            legit.queries = request.queries.clone();
            let _ = socket.send_to(&legit.to_vec().unwrap(), client).await;
        });

        let exchange = super::UdpExchange::new(peer, localhost_dial());
        let request = query("example.com.");
        let response = exchange.query(wire_query(request)).await.unwrap();
        assert_eq!(
            response.queries.first().map(|q| q.name().to_string()),
            Some("example.com.".to_string())
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn junk_answers_cannot_delay_retransmit() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = socket.local_addr().unwrap();
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = received.clone();
        let server = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, client)) = socket.recv_from(&mut buf).await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let Ok(request) = Message::from_vec(&buf[..len]) else { continue };
                let mut forged = Message::response(request.metadata.id, request.op_code);
                forged.queries =
                    vec![Query::query(Name::parse("evil.example.", None).unwrap(), RecordType::A)];
                let _ = socket.send_to(&forged.to_vec().unwrap(), client).await;
            }
        });

        let exchange = super::UdpExchange::new(peer, localhost_dial());
        let mut options = DnsRequestOptions::default();
        options.retry_interval = Duration::from_millis(40);
        let query = Query::query(Name::parse("example.com.", None).unwrap(), RecordType::A);
        let request = DnsRequest::from_query(query, options);

        let allowance =
            crate::exp_conn_pool::allowance::TimeAllowance::new(Duration::from_millis(300));
        let outcome = allowance.complete_within(exchange.query(wire_query(request))).await;
        assert!(matches!(outcome, Err(hickory_resolver::net::NetError::Timeout)));
        assert!(
            received.load(std::sync::atomic::Ordering::SeqCst) >= 3,
            "retransmissions must not be postponed by junk answers"
        );
        server.abort();
    }

    #[tokio::test]
    async fn retry_interval_has_a_floor() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = socket.local_addr().unwrap();
        let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while socket.recv_from(&mut buf).await.is_ok() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let exchange = super::UdpExchange::new(peer, localhost_dial());
        let mut options = DnsRequestOptions::default();
        options.retry_interval = Duration::from_millis(1);
        let query = Query::query(Name::parse("example.com.", None).unwrap(), RecordType::A);
        let request = DnsRequest::from_query(query, options);

        let allowance =
            crate::exp_conn_pool::allowance::TimeAllowance::new(Duration::from_millis(200));
        let outcome = allowance.complete_within(exchange.query(wire_query(request))).await;
        assert!(matches!(outcome, Err(hickory_resolver::net::NetError::Timeout)));
        let count = received.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            (5..=40).contains(&count),
            "retransmit count {count} escapes the retry-interval floor"
        );
    }

    fn test_pool(peer: std::net::SocketAddr) -> Arc<super::UdpSocketPool> {
        Arc::new(super::UdpSocketPool {
            peer,
            dial: localhost_dial(),
            idle: std::sync::Mutex::new(std::collections::VecDeque::new()),
        })
    }

    #[tokio::test]
    async fn socket_is_retired_after_reuse_budget() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = test_pool(server.local_addr().unwrap());

        let mut entry = pool.create_socket().unwrap();
        entry.uses = super::UDP_SOCKET_MAX_REUSES;
        pool.put(entry);
        assert_eq!(
            pool.idle.lock().unwrap().len(),
            0,
            "a socket past its reuse budget must be retired, not requeued"
        );
        let checked = pool.checkout().unwrap();
        assert!(checked.socket().local_addr().is_ok());
    }

    #[tokio::test]
    async fn socket_is_retired_after_max_age() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = test_pool(server.local_addr().unwrap());

        let mut entry = pool.create_socket().unwrap();
        entry.created = std::time::Instant::now() - super::UDP_SOCKET_MAX_AGE;
        pool.put(entry);
        assert_eq!(
            pool.idle.lock().unwrap().len(),
            0,
            "a socket older than UDP_SOCKET_MAX_AGE must be retired"
        );
    }

    #[tokio::test]
    async fn checkout_replaces_idle_socket_that_aged_out() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pool = test_pool(server.local_addr().unwrap());

        pool.idle.lock().unwrap().push_back(pool.create_socket().unwrap());
        pool.idle.lock().unwrap().front_mut().unwrap().created =
            std::time::Instant::now() - super::UDP_SOCKET_MAX_AGE;

        let checked = pool.checkout().unwrap();
        assert!(
            pool.idle.lock().unwrap().is_empty(),
            "an aged idle socket must be dropped on checkout, not reused"
        );
        assert!(checked.socket().local_addr().is_ok());
    }
}
