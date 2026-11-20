//! Connected UDP sockets multiplex requests by their upstream DNS ID. A socket
//! stops accepting queries after its use or age limit. Outstanding queries
//! keep it alive until they finish.

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Message, Query};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, Semaphore, oneshot};
use tokio::task::JoinHandle;

use crate::upstream::native::mark::MarkRuntimeProvider;
use crate::upstream::native::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

use super::{build_message, classify_message};

const UDP_SOCKET_POOL_SIZE: usize = 4;
const UDP_SOCKET_MAX_USES: usize = 64;
const UDP_SOCKET_MAX_AGE: Duration = Duration::from_secs(30);

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
            addr: self.addr,
            provider: self.provider.clone(),
            sockets: AsyncMutex::new(Vec::new()),
            capacity: Semaphore::new(UDP_SOCKET_POOL_SIZE * UDP_SOCKET_MAX_USES),
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

struct UdpConn {
    addr: SocketAddr,
    provider: MarkRuntimeProvider,
    sockets: AsyncMutex<Vec<Arc<SharedSocket>>>,
    capacity: Semaphore,
    query_timeout: Duration,
}

impl Debug for UdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpConn").field("addr", &self.addr).finish()
    }
}

struct Pending {
    message: Message,
    limit: usize,
    reply: oneshot::Sender<Message>,
}

// Keep used IDs until this socket closes. Rotation bounds the table to 64
// entries and even an identical late question cannot match a later request.
#[derive(Default)]
struct SocketState {
    requests: HashMap<u16, Option<Pending>>,
    failed: bool,
}

struct SharedSocket {
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<SocketState>>,
    created: Instant,
    reader: JoinHandle<()>,
}

impl Drop for SharedSocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl SharedSocket {
    fn new(socket: UdpSocket) -> Arc<Self> {
        let socket = Arc::new(socket);
        let state = Arc::new(Mutex::new(SocketState::default()));
        let reader = tokio::spawn(read_responses(socket.clone(), state.clone()));
        Arc::new(Self { socket, state, reader, created: Instant::now() })
    }

    fn accepting(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.failed
            && state.requests.len() < UDP_SOCKET_MAX_USES
            && self.created.elapsed() < UDP_SOCKET_MAX_AGE
    }
}

async fn read_responses(socket: Arc<UdpSocket>, state: Arc<Mutex<SocketState>>) {
    let mut buffer = vec![0; 65536];
    loop {
        let size = match socket.recv(&mut buffer).await {
            Ok(size) => size,
            Err(_) => {
                let mut state = state.lock().unwrap();
                state.failed = true;
                state.requests.clear();
                return;
            }
        };
        if size < 2 {
            continue;
        }
        let id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let mut state = state.lock().unwrap();
        let Some(slot) = state.requests.get_mut(&id) else { continue };
        let Some(request) = slot.as_ref() else { continue };
        let bytes = &buffer[..size.min(request.limit)];
        let response = match Message::from_vec(bytes) {
            Ok(response) if validate_response(&response, &request.message) => response,
            Ok(_) => continue,
            Err(_) => match truncated_response(bytes, &request.message) {
                Some(response) => response,
                None => continue,
            },
        };
        let _ = slot.take().unwrap().reply.send(response);
    }
}

struct PendingQuery {
    socket: Arc<SharedSocket>,
    id: u16,
}

impl Drop for PendingQuery {
    fn drop(&mut self) {
        if let Some(slot) = self.socket.state.lock().unwrap().requests.get_mut(&self.id) {
            slot.take();
        }
    }
}

impl UdpConn {
    async fn register(&self, mut request: Pending) -> Result<PendingQuery, DnsConnError> {
        let mut sockets = self.sockets.lock().await;
        sockets.retain(|socket| socket.accepting());
        // Only the pool and live query guards hold SharedSocket references.
        let least_busy = sockets.iter().min_by_key(|socket| Arc::strong_count(socket));
        let socket = match least_busy {
            Some(socket)
                if Arc::strong_count(socket) == 1 || sockets.len() == UDP_SOCKET_POOL_SIZE =>
            {
                socket.clone()
            }
            _ => {
                let bound = self
                    .provider
                    .bind_udp(self.addr)
                    .await
                    .map_err(|e| DnsConnError::Io(e.to_string()))?;
                let socket = SharedSocket::new(bound);
                sockets.push(socket.clone());
                socket
            }
        };
        let mut state = socket.state.lock().unwrap();
        if state.failed {
            return Err(DnsConnError::Io("UDP socket closed".into()));
        }
        let id = loop {
            let id = rand::random();
            if !state.requests.contains_key(&id) {
                break id;
            }
        };
        request.message.metadata.id = id;
        state.requests.insert(id, Some(request));
        drop(state);
        Ok(PendingQuery { socket, id })
    }
}

#[async_trait]
impl DnsConn for UdpConn {
    async fn query(
        &self,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError> {
        let _permit = self.capacity.try_acquire().map_err(|_| DnsConnError::NoConnections)?;
        tokio::time::timeout(self.query_timeout, async {
            let (reply, result) = oneshot::channel();
            let request = Pending {
                message: build_message(query, options),
                limit: usize::from(options.edns_payload_len.max(512)),
                reply,
            };
            let mut bytes =
                request.message.to_vec().map_err(|e| DnsConnError::Internal(e.to_string()))?;
            let guard = self.register(request).await?;
            bytes[..2].copy_from_slice(&guard.id.to_be_bytes());
            guard.socket.socket.send(&bytes).await.map_err(|e| DnsConnError::Io(e.to_string()))?;
            let response =
                result.await.map_err(|_| DnsConnError::Io("UDP socket closed".into()))?;
            classify_message(response)
        })
        .await
        .map_err(|_| DnsConnError::Timeout)?
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Udp
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    fn shutdown(&self) {
        // The outer pool drops its handle on retirement. In-flight queries
        // retain their socket until their reply or cancellation.
    }
}

/// Ignore datagrams that cannot be correlated with this lookup.
fn validate_response(response: &Message, query: &Message) -> bool {
    response.metadata.id == query.metadata.id
        && super::validate_reply(response, &query.queries).is_ok()
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

    async fn endpoint(server: &UdpSocket) -> Arc<dyn DnsConn> {
        UdpConnector {
            addr: server.local_addr().unwrap(),
            provider: MarkRuntimeProvider::new(0, Default::default()),
            query_timeout: Duration::from_secs(2),
        }
        .connect()
        .await
        .unwrap()
    }

    async fn start_query(
        conn: &Arc<dyn DnsConn>,
        server: &UdpSocket,
    ) -> (tokio::task::JoinHandle<Result<Message, DnsConnError>>, Message, SocketAddr) {
        let conn = conn.clone();
        let handle = tokio::spawn(async move {
            conn.query(&query().queries[0], &DnsRequestOptions::default()).await
        });
        let mut buf = [0; 512];
        let (size, addr) = tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        (handle, Message::from_vec(&buf[..size]).unwrap(), addr)
    }

    async fn respond(server: &UdpSocket, request: &Message, addr: SocketAddr) {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.queries.clone_from(&request.queries);
        response.answers.push(Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
        ));
        server.send_to(&response.to_vec().unwrap(), addr).await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_queries_match_on_their_socket_in_reverse_order() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let conn = endpoint(&server).await;
        let mut pending = Vec::new();
        let mut ids = std::collections::HashSet::new();
        let mut ports = std::collections::HashSet::new();
        for _ in 0..(UDP_SOCKET_POOL_SIZE * 2) {
            let (handle, message, addr) = start_query(&conn, &server).await;
            assert!(ids.insert((addr, message.metadata.id)));
            ports.insert(addr);
            pending.push((handle, message, addr));
        }
        assert_eq!(ports.len(), UDP_SOCKET_POOL_SIZE);
        for (handle, message, addr) in pending.into_iter().rev() {
            respond(&server, &message, addr).await;
            assert_eq!(handle.await.unwrap().unwrap().metadata.id, message.metadata.id);
        }
    }

    #[tokio::test]
    async fn cancel_at_capacity_admits_one_query_and_preserves_other_waiters() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let conn = UdpConnector {
            addr: server.local_addr().unwrap(),
            provider: MarkRuntimeProvider::new(0, Default::default()),
            query_timeout: Duration::from_secs(30),
        }
        .connect()
        .await
        .unwrap();
        let mut pending = Vec::new();
        for _ in 0..UDP_SOCKET_POOL_SIZE * UDP_SOCKET_MAX_USES {
            pending.push(start_query(&conn, &server).await);
        }
        let overflow = conn.query(&query().queries[0], &DnsRequestOptions::default()).await;
        assert!(matches!(overflow, Err(DnsConnError::NoConnections)));

        let (canceled, old_message, old_addr) = pending.pop().unwrap();
        canceled.abort();
        assert!(canceled.await.unwrap_err().is_cancelled());
        let (replacement, new_message, new_addr) = start_query(&conn, &server).await;
        respond(&server, &old_message, old_addr).await;
        respond(&server, &new_message, new_addr).await;
        assert_eq!(replacement.await.unwrap().unwrap().metadata.id, new_message.metadata.id);
        for (task, message, addr) in pending.into_iter().rev() {
            respond(&server, &message, addr).await;
            assert_eq!(task.await.unwrap().unwrap().metadata.id, message.metadata.id);
        }
    }

    #[tokio::test]
    async fn canceled_ids_stay_retired_and_idle_socket_rotates() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let conn = endpoint(&server).await;
        let (handle, canceled, first_addr) = start_query(&conn, &server).await;
        handle.abort();
        let _ = handle.await;
        let mut ids = std::collections::HashSet::from([canceled.metadata.id]);
        for _ in 1..UDP_SOCKET_MAX_USES - 1 {
            let (handle, message, addr) = start_query(&conn, &server).await;
            assert_eq!(addr, first_addr);
            assert!(ids.insert(message.metadata.id));
            respond(&server, &canceled, first_addr).await;
            respond(&server, &message, addr).await;
            assert_eq!(handle.await.unwrap().unwrap().metadata.id, message.metadata.id);
        }
        let (last, old_message, old_addr) = start_query(&conn, &server).await;
        assert_eq!(old_addr, first_addr);
        let (handle, message, addr) = start_query(&conn, &server).await;
        assert_ne!(addr, old_addr);
        respond(&server, &message, addr).await;
        assert!(handle.await.unwrap().is_ok());
        respond(&server, &old_message, old_addr).await;
        assert!(last.await.unwrap().is_ok());
        let (next, message, next_addr) = start_query(&conn, &server).await;
        assert_eq!(next_addr, addr);
        respond(&server, &message, next_addr).await;
        assert!(next.await.unwrap().is_ok());
    }

    #[test]
    fn validates_id() {
        let mut wrong_id = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_id.metadata.id = 0x9999;
        assert!(!validate_response(&wrong_id, &query()));
    }

    #[test]
    fn validates_question_echo() {
        // A response answering a different question is forged.
        let mut wrong_question = coded_response(hickory_proto::op::ResponseCode::NoError);
        wrong_question
            .queries
            .push(Query::query(Name::from_str("other.com.").unwrap(), RecordType::A));
        assert!(!validate_response(&wrong_question, &query()));

        // The exact echoed question is accepted.
        let mut echoed = coded_response(hickory_proto::op::ResponseCode::NoError);
        echoed.queries.clone_from(&query().queries);
        assert!(validate_response(&echoed, &query()));
    }

    #[test]
    fn rejects_non_response_messages() {
        assert!(!validate_response(&query(), &query()));
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
