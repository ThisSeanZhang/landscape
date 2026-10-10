//! A DNS-over-stream multiplexer: one connection, many concurrent queries.
//!
//! A single task owns the stream (read half through a length-delimited frame
//! decoder, write half directly). Every query is assigned a random message
//! id; responses are dispatched by id. The semantics mirror hickory-net's
//! `DnsMultiplexer`:
//! - an in-flight cap (`max_active_requests`) surfaces as the capacity class
//!   (`NoConnections`), so pressure never counts against the connection's
//!   health;
//! - an abandoned query (caller timeout) is released from the map lazily;
//! - a stream error or peer close fails every in-flight query with a real
//!   connection error — hickory-net instead conflated a disconnected channel
//!   with "busy", which kept dead connections in the pool forever.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use hickory_proto::op::{DnsRequestOptions, Message, MessageType, Query};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

use crate::connection::upstream::pool_config::STREAM_CAPACITY_WAIT;
use crate::connection::upstream::traits::{DnsConn, DnsConnError, DnsTransport};

use super::{build_message, classify_message};

/// One queued request on a multiplexed stream connection.
struct Request {
    message: Message,
    reply: oneshot::Sender<Result<Message, DnsConnError>>,
    /// When the caller gives up waiting (its `query_timeout` budget).
    deadline: Instant,
}

/// An outstanding request the mux task has written to the wire: the reply
/// channel, the caller's deadline, and the request's question section (for
/// response validation).
type Pending = (oneshot::Sender<Result<Message, DnsConnError>>, Instant, Vec<Query>);

/// The caller-facing handle of a multiplexed stream connection. Clones share
/// the underlying stream; the last handle dropped ends the mux task.
#[derive(Clone)]
pub(super) struct MuxConn {
    tx: mpsc::Sender<Request>,
    cap: Arc<Semaphore>,
    ip: IpAddr,
    query_timeout: Duration,
    /// Test-only protocol tag (`"Tcp"`, `"Tls"`).
    #[cfg_attr(not(test), allow(dead_code))]
    tag: &'static str,
}

impl std::fmt::Debug for MuxConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxConn").field("ip", &self.ip).field("tag", &self.tag).finish()
    }
}

impl MuxConn {
    /// Wraps an established stream in a multiplexer task.
    pub(super) fn spawn<S>(
        stream: S,
        ip: IpAddr,
        query_timeout: Duration,
        max_active_requests: usize,
        tag: &'static str,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (tx, rx) = mpsc::channel(max_active_requests.saturating_mul(2).max(4));
        tokio::spawn(mux_task(stream, rx));
        Self {
            tx,
            cap: Arc::new(Semaphore::new(max_active_requests.max(1))),
            ip,
            query_timeout,
            tag,
        }
    }
}

#[async_trait]
impl DnsConn for MuxConn {
    async fn query(
        &self,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError> {
        // The in-flight cap mirrors the multiplexer's "busy" signal: it is a
        // capacity condition, not a connectivity failure, so the pool never
        // counts it against the connection or the upstream's health.
        let permit =
            self.cap.clone().try_acquire_owned().map_err(|_| DnsConnError::NoConnections)?;

        let (reply, rx) = oneshot::channel();
        let deadline = std::time::Instant::now()
            .checked_add(self.query_timeout)
            .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(1));
        let request = Request {
            message: build_message(query, options),
            reply,
            deadline,
        };

        // A full channel means the mux task is not draining (its write side
        // is stalled against a peer that stopped reading): a capacity
        // condition, surfaced fast instead of parking into a health-counted
        // Timeout. A closed channel means the mux task exited.
        let result = match tokio::time::timeout(STREAM_CAPACITY_WAIT, self.tx.send(request)).await {
            Ok(Ok(())) => tokio::time::timeout(self.query_timeout, rx).await,
            Ok(Err(_)) => return Err(DnsConnError::Io("connection closed".into())),
            Err(_) => return Err(DnsConnError::NoConnections),
        };
        drop(permit);

        match result {
            // The mux task replied (success or a classified failure).
            Ok(Ok(outcome)) => outcome,
            // The reply sender was dropped by the mux task without a result:
            // it failed or shut down the connection.
            Ok(Err(_)) => Err(DnsConnError::Io("connection closed".into())),
            Err(_) => Err(DnsConnError::Timeout),
        }
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Stream
    }

    fn ip(&self) -> IpAddr {
        self.ip
    }

    fn shutdown(&self) {
        // Drop-based teardown (hickory parity): the mux task exits when the
        // last `MuxConn` handle is dropped, which happens when the pool
        // retires the connection and no lookup is in flight on it.
    }
}

/// Owns the stream: reads length-prefixed frames, dispatches responses by
/// id, writes outbound frames, and tears everything down on failure.
async fn mux_task<S>(stream: S, mut rx: mpsc::Receiver<Request>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    // DNS-over-TCP framing (RFC 1035 §4.2.2): a 2-octet length followed by
    // the message; the length field bounds a frame at 64 KiB.
    let codec = LengthDelimitedCodec::builder()
        .length_field_length(2)
        .big_endian()
        .max_frame_length(u16::MAX as usize)
        .new_codec();
    let mut framed = FramedRead::new(read, codec);
    let mut active: HashMap<u16, Pending> = HashMap::new();

    loop {
        tokio::select! {
            maybe_req = rx.recv() => {
                let Some(req) = maybe_req else { break };
                // Purge entries whose caller already gave up (they can never
                // receive the response); bounds the map when responses never
                // arrive.
                let now = Instant::now();
                active.retain(|_, (_, deadline, _)| *deadline > now);
                let Some(id) = next_random_id(&active) else {
                    let _ = req.reply.send(Err(DnsConnError::NoConnections));
                    continue;
                };
                let mut message = req.message;
                message.metadata.id = id;
                let Ok(bytes) = message.to_vec() else {
                    let _ = req.reply.send(Err(DnsConnError::Internal("message encode failed".into())));
                    continue;
                };
                let Some(frame) = frame_bytes(&bytes) else {
                    let _ = req.reply.send(Err(DnsConnError::Internal(
                        "message exceeds the 65535-byte stream limit".into(),
                    )));
                    continue;
                };
                // The write is bounded by the request's own deadline: a peer
                // that accepts the connection but never reads (TCP zero
                // window) would otherwise park this task inside `write_all`
                // forever — and a parked task no longer polls the read side,
                // cannot observe the channel closing, and leaks the task and
                // socket (violating the `DnsConn` "must never block
                // indefinitely" contract).
                let written = tokio::time::timeout_at(
                    tokio::time::Instant::from(req.deadline),
                    write.write_all(&frame),
                )
                .await;
                match written {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        fail_all(&mut active, DnsConnError::Io(format!("stream write failed: {e}")));
                        let _ = req.reply.send(Err(DnsConnError::Io(format!(
                            "stream write failed: {e}"
                        ))));
                        break;
                    }
                    Err(_) => {
                        fail_all(&mut active, DnsConnError::Io("stream write timed out".into()));
                        let _ =
                            req.reply.send(Err(DnsConnError::Io("stream write timed out".into())));
                        break;
                    }
                }
                active.insert(id, (req.reply, req.deadline, message.queries.clone()));
            }
            frame = framed.next() => {
                match frame {
                    Some(Ok(bytes)) => {
                        match Message::from_vec(&bytes) {
                            Ok(message) if message.metadata.message_type == MessageType::Response => {
                                if let Some((reply, deadline, expected)) = active.remove(&message.metadata.id) {
                                    // Same contract as the UDP validator
                                    // (hickory's `validate_response`): every
                                    // question in the response must echo the
                                    // request. A mismatched frame (forged or
                                    // cross-wired) must not satisfy the
                                    // pending query: re-queue it and keep
                                    // waiting — the caller's timeout bounds
                                    // the wait, and the connection survives.
                                    if !message.queries.iter().all(|q| expected.contains(q)) {
                                        tracing::debug!(
                                            id = message.metadata.id,
                                            "dropping response with mismatched question"
                                        );
                                        active.insert(message.metadata.id, (reply, deadline, expected));
                                        continue;
                                    }
                                    // Every response passes the same RCODE
                                    // classification as UDP: an explicit
                                    // error code or empty negative answer
                                    // must surface as `Protocol(..)`, never
                                    // as a successful (empty) message.
                                    let _ = reply.send(classify_message(message));
                                } else {
                                    tracing::debug!(
                                        id = message.metadata.id,
                                        "dropping response with unknown message id"
                                    );
                                }
                            }
                            Ok(_) => tracing::debug!("dropping non-response frame"),
                            Err(e) => tracing::debug!("dropping undecodable frame: {e}"),
                        }
                    }
                    Some(Err(e)) => {
                        fail_all(&mut active, DnsConnError::Io(format!("stream error: {e}")));
                        break;
                    }
                    // EOF: the peer closed the connection.
                    None => {
                        fail_all(&mut active, DnsConnError::Io("connection closed by peer".into()));
                        break;
                    }
                }
            }
        }
    }
}

/// A length-prefixed wire frame for one message, or `None` when the message
/// exceeds the 65535-byte bound of the 2-octet length field (refused loudly
/// instead of wrapping the length into a corrupt frame).
fn frame_bytes(message: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(message.len()).ok()?;
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    Some(frame)
}

/// Picks a random id not currently in flight (mirrors hickory's
/// `next_random_query_id`: up to 100 draws before giving up).
fn next_random_id(active: &HashMap<u16, Pending>) -> Option<u16> {
    for _ in 0..100 {
        let id: u16 = rand::random();
        if !active.contains_key(&id) {
            return Some(id);
        }
    }
    None
}

/// Fails every in-flight query with `error`.
fn fail_all(active: &mut HashMap<u16, Pending>, error: DnsConnError) {
    for (_, (reply, _, _)) in active.drain() {
        let _ = reply.send(Err(error.clone()));
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::connection::upstream::traits::DnsConn;
    use hickory_proto::rr::rdata::A;

    use super::*;

    fn query() -> Query {
        Query::query(Name::from_str("example.com.").unwrap(), RecordType::A)
    }

    fn options() -> DnsRequestOptions {
        DnsRequestOptions::default()
    }

    /// A response echoing the given request (id copied from the request).
    fn response_for(request: &Message) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.queries.clone_from(&request.queries);
        let name = request.queries[0].name().clone();
        response.answers.push(Record::from_rdata(
            name,
            60,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        ));
        response
    }

    /// A duplex pair: `client` is handed to the mux; `server` is the peer the
    /// test drives directly.
    async fn mux_pair() -> (MuxConn, TcpStream) {
        mux_pair_with_timeout(Duration::from_secs(5)).await
    }

    async fn mux_pair_with_timeout(query_timeout: Duration) -> (MuxConn, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let server = server.await.unwrap();
        let conn = MuxConn::spawn(client, addr.ip(), query_timeout, 32, "Tcp");
        (conn, server)
    }

    async fn mux_pair_with_cap(cap: usize) -> (MuxConn, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let server = server.await.unwrap();
        let conn = MuxConn::spawn(client, addr.ip(), Duration::from_secs(5), cap, "Tcp");
        (conn, server)
    }

    /// Reads one length-prefixed frame from the test peer.
    async fn read_frame(server: &mut TcpStream) -> Message {
        let mut len = [0u8; 2];
        server.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
        server.read_exact(&mut body).await.unwrap();
        Message::from_vec(&body).unwrap()
    }

    /// Writes one length-prefixed response to the test peer.
    async fn write_response(server: &mut TcpStream, response: &Message) {
        let bytes = response.to_vec().unwrap();
        let mut frame = Vec::with_capacity(2 + bytes.len());
        frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        frame.extend_from_slice(&bytes);
        server.write_all(&frame).await.unwrap();
    }

    /// A single query round-trips: random id, echoed question, answer
    /// classified back to the caller.
    #[tokio::test]
    async fn query_round_trip() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &response_for(&request)).await;

        let message = query_task.await.unwrap().unwrap();
        assert_eq!(message.answers.len(), 1);
        assert!(matches!(message.answers[0].data, RData::A(A(_))));
        conn.shutdown();
    }

    /// Concurrent queries get distinct ids and are dispatched correctly.
    #[tokio::test]
    async fn concurrent_queries_get_distinct_ids() {
        let (conn, mut server) = mux_pair().await;
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let conn = conn.clone();
            tasks.push(tokio::spawn(async move {
                let q = Query::query(Name::from_str("example.com.").unwrap(), RecordType::A);
                conn.query(&q, &options()).await.unwrap()
            }));
        }
        let mut ids = std::collections::HashSet::new();
        let mut responses = Vec::new();
        for _ in 0..8 {
            let request = read_frame(&mut server).await;
            assert!(ids.insert(request.metadata.id), "id {} reused", request.metadata.id);
            let response = response_for(&request);
            write_response(&mut server, &response).await;
            responses.push(response);
        }
        // Every task receives the answer carrying its own random id: the
        // mux dispatches by id, never cross-wiring responses.
        let mut returned: Vec<u16> = Vec::new();
        for task in tasks {
            let message = task.await.unwrap();
            assert!(message.answers.len() == 1);
            returned.push(message.metadata.id);
        }
        returned.sort_unstable();
        let mut expected: Vec<u16> = ids.into_iter().collect();
        expected.sort_unstable();
        assert_eq!(returned, expected);
        conn.shutdown();
    }

    /// A query whose id response never arrives times out; the id is released
    /// so a later query can reuse it, and the connection stays healthy.
    #[tokio::test]
    async fn timed_out_query_releases_id_and_connection_stays_healthy() {
        let (conn, mut server) = mux_pair_with_timeout(Duration::from_millis(50)).await;

        let timeout_result = conn.query(&query(), &options()).await;
        assert!(matches!(timeout_result, Err(DnsConnError::Timeout)));

        // The timed-out request still reaches the wire; the response arrives
        // late and must be dropped (the caller is gone).
        let request = read_frame(&mut server).await;
        write_response(&mut server, &response_for(&request)).await;

        // A follow-up query succeeds on the same connection.
        let query_task = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &response_for(&request)).await;
        assert!(query_task.await.unwrap().is_ok());

        conn.shutdown();
    }

    /// A peer close fails every in-flight query and every later query
    /// reports the close (the pool then retires the connection).
    #[tokio::test]
    async fn peer_close_fails_in_flight_queries() {
        let (conn, mut server) = mux_pair().await;
        let in_flight = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });
        // Let the request reach the wire, then kill the connection.
        let _request = read_frame(&mut server).await;
        drop(server);

        let err = in_flight.await.unwrap().unwrap_err();
        assert!(matches!(err, DnsConnError::Io(_)), "expected Io, got {err:?}");

        // A later query on the (now dead) conn fails fast with Io.
        let err = conn.query(&query(), &options()).await.unwrap_err();
        assert!(matches!(err, DnsConnError::Io(_)), "expected Io, got {err:?}");
        conn.shutdown();
    }

    /// A garbage frame is dropped without killing the connection.
    #[tokio::test]
    async fn garbage_frame_is_dropped_connection_survives() {
        let (conn, mut server) = mux_pair().await;
        server.write_all(&[0, 3, 0xde, 0xad, 0xbe]).await.unwrap();

        let query_task = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &response_for(&request)).await;
        assert!(query_task.await.unwrap().is_ok());
        conn.shutdown();
    }

    /// A response echoing the right id but a different question (forged or
    /// cross-wired) must not satisfy the pending query — same contract as
    /// the UDP validator: the frame is dropped, the connection survives,
    /// and the real answer still completes the query.
    #[tokio::test]
    async fn mismatched_question_response_is_dropped() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;

        // Forged frame: correct id, wrong question, enticing answer.
        let mut forged = Message::response(request.metadata.id, OpCode::Query);
        forged
            .queries
            .push(Query::query(Name::from_str("evil.example.com.").unwrap(), RecordType::TXT));
        forged.answers.push(Record::from_rdata(
            Name::from_str("evil.example.com.").unwrap(),
            60,
            RData::A(A(std::net::Ipv4Addr::new(6, 6, 6, 6))),
        ));
        write_response(&mut server, &forged).await;

        // The real answer still completes the query.
        write_response(&mut server, &response_for(&request)).await;
        let message = query_task.await.unwrap().unwrap();
        assert_eq!(message.queries, request.queries, "the forged frame must not satisfy the query");
        assert_eq!(message.answers.len(), 1);
        conn.shutdown();
    }

    /// The in-flight cap surfaces as the capacity class.
    #[tokio::test]
    async fn in_flight_cap_is_capacity_class() {
        let (conn, mut server) = mux_pair_with_cap(1).await;

        // First query occupies the only slot.
        let first = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });
        let request = read_frame(&mut server).await;

        // Second query hits the cap immediately.
        let err = conn.query(&query(), &options()).await.unwrap_err();
        assert!(matches!(err, DnsConnError::NoConnections));

        write_response(&mut server, &response_for(&request)).await;
        assert!(first.await.unwrap().is_ok());
        // The slot is free again.
        let second = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &response_for(&request)).await;
        assert!(second.await.unwrap().is_ok());

        conn.shutdown();
    }

    /// An error-code response echoing the request (id and question copied,
    /// no records) — the shape a resolver returns for SERVFAIL/REFUSED or an
    /// authoritative NXDOMAIN.
    fn error_response_for(request: &Message, code: ResponseCode) -> Message {
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.queries.clone_from(&request.queries);
        response.metadata.response_code = code;
        response
    }

    /// P0 regression: an upstream SERVFAIL must surface as
    /// `Protocol(ServFail)` — never as a successful empty answer the pool
    /// would cache as NOERROR and fan-out would treat as a verdict.
    #[tokio::test]
    async fn servfail_response_surfaces_as_protocol_error() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &error_response_for(&request, ResponseCode::ServFail)).await;

        let err = query_task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, DnsConnError::Protocol(ResponseCode::ServFail, None)),
            "expected Protocol(ServFail), got {err:?}"
        );
        conn.shutdown();
    }

    /// Same contract for REFUSED (rate-limited / policy rejection).
    #[tokio::test]
    async fn refused_response_surfaces_as_protocol_error() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &error_response_for(&request, ResponseCode::Refused)).await;

        let err = query_task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, DnsConnError::Protocol(ResponseCode::Refused, None)),
            "expected Protocol(Refused), got {err:?}"
        );
        conn.shutdown();
    }

    /// A negative NXDomain keeps its authority-section SOA (RFC 2308
    /// negative caching) through the mux.
    #[tokio::test]
    async fn empty_nxdomain_with_soa_surfaces_as_protocol_with_soa() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        let mut response = error_response_for(&request, ResponseCode::NXDomain);
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("example.com.").unwrap(),
                Name::from_str("ns.example.com.").unwrap(),
                1,
                1,
                1,
                1,
                60,
            )),
        ));
        write_response(&mut server, &response).await;

        let err = query_task.await.unwrap().unwrap_err();
        match err {
            DnsConnError::Protocol(code, Some(soa)) => {
                assert_eq!(code, ResponseCode::NXDomain);
                assert_eq!(soa.ttl, 300);
                assert!(matches!(soa.data, RData::SOA(_)));
            }
            other => panic!("expected Protocol(NXDomain, soa), got {other:?}"),
        }
        conn.shutdown();
    }

    /// A NoData answer (NoError with no records and an authority SOA) is a
    /// negative answer over streams too, surfacing as
    /// `Protocol(NoError, soa)` for RFC 2308 negative caching.
    #[tokio::test]
    async fn nodata_with_soa_surfaces_as_protocol_noerror() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        let mut response = error_response_for(&request, ResponseCode::NoError);
        response.authorities.push(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_str("example.com.").unwrap(),
                Name::from_str("ns.example.com.").unwrap(),
                1,
                1,
                1,
                1,
                60,
            )),
        ));
        write_response(&mut server, &response).await;

        let err = query_task.await.unwrap().unwrap_err();
        match err {
            DnsConnError::Protocol(code, Some(soa)) => {
                assert_eq!(code, ResponseCode::NoError);
                assert_eq!(soa.ttl, 300);
            }
            other => panic!("expected Protocol(NoError, soa), got {other:?}"),
        }
        conn.shutdown();
    }

    /// A truncated response passes through unclassified (with the TC bit
    /// preserved): the pool's truncation handling — stream retry or
    /// surfacing the partial answer with the flag — owns it from there.
    #[tokio::test]
    async fn truncated_response_passes_through_with_tc_bit() {
        let (conn, mut server) = mux_pair().await;
        let query_task = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        let mut response = error_response_for(&request, ResponseCode::NoError);
        response.metadata.truncation = true;
        write_response(&mut server, &response).await;

        let message = query_task.await.unwrap().unwrap();
        assert!(message.metadata.truncation, "the TC bit must survive the mux");
        conn.shutdown();
    }

    /// A protocol-classified answer is final for the query, not for the
    /// connection: the stream stays pooled and the next query succeeds.
    #[tokio::test]
    async fn protocol_error_does_not_kill_connection() {
        let (conn, mut server) = mux_pair().await;
        let first = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &error_response_for(&request, ResponseCode::ServFail)).await;
        assert!(matches!(first.await.unwrap(), Err(DnsConnError::Protocol(..))));

        let second = tokio::spawn({
            let conn = conn.clone();
            let q = query();
            async move { conn.query(&q, &options()).await }
        });
        let request = read_frame(&mut server).await;
        write_response(&mut server, &response_for(&request)).await;
        assert!(second.await.unwrap().is_ok());
        conn.shutdown();
    }

    /// D-2 regression: a peer that accepts the connection but never reads
    /// (TCP zero window) must not park the mux task inside `write_all`
    /// forever — a parked task stops polling the read side, can no longer
    /// observe the channel closing, and leaks the task and socket. The
    /// write is bounded by the request's own deadline; on expiry the whole
    /// connection is torn down.
    #[tokio::test]
    async fn zero_window_peer_write_times_out_and_tears_down() {
        // A tiny in-memory pipe stands in for the kernel socket buffer:
        // once full, `write_all` blocks exactly like a zero-window TCP
        // peer, and the test controls the reader (it never reads). The
        // first query's frame (~31 bytes) fits the 48-byte buffer; the
        // second's cannot and stalls until its deadline fires.
        let (client, _server) = tokio::io::duplex(48);
        let conn = MuxConn::spawn(
            client,
            "127.0.0.1".parse().unwrap(),
            Duration::from_millis(100),
            32,
            "Tcp",
        );

        // First query: its frame is written into the pipe buffer and the
        // caller waits for a response that will never come.
        let first = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });
        // Second query: its write stalls against the full pipe until the
        // request deadline expires.
        let second = tokio::spawn({
            let conn = conn.clone();
            async move { conn.query(&query(), &options()).await }
        });

        // Both callers must fail within their budget: the stalled one
        // either times out at the write (`Io("stream write timed out")`)
        // or — in the same poll cycle, since the write deadline *is* the
        // caller's deadline — its own wait times out. Neither may hang.
        for task in [first, second] {
            let outcome = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("query must not hang past its budget")
                .unwrap();
            match outcome {
                Err(DnsConnError::Timeout) => {}
                Err(DnsConnError::Io(m)) if m.contains("stream write timed out") => {}
                other => panic!("expected a budgeted failure, got {other:?}"),
            }
        }

        // The expired write tears the whole connection down: the mux task
        // has exited, so a later query fails fast with the close signal
        // instead of queueing into the dead channel. (With the write
        // deadline reverted, the mux task would stay parked forever and
        // this loop would time out with `Timeout` outcomes.)
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "the stalled write must tear the connection down"
            );
            let outcome = conn.query(&query(), &options()).await;
            match outcome {
                Err(DnsConnError::Io(m)) if m.contains("connection closed") => break,
                Err(DnsConnError::Timeout) => tokio::time::sleep(Duration::from_millis(10)).await,
                other => panic!("expected the closed-connection Io, got {other:?}"),
            }
        }
    }
}
