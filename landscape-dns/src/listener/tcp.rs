//! Plain DNS over TCP (RFC 7766 framing) for one flow.
//!
//! Each flow owns one TCP listening socket bound to the same port as its UDP
//! socket. The per-flow reuseport dispatcher selects the listener before the
//! handshake completes, so every accepted connection already belongs to this
//! flow and is served by the same [`DnsRequestHandler`], cache and upstream
//! policy as UDP queries.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use landscape_common::concurrency::task_label;

use crate::listener::wire::{self, MAX_EDNS_PAYLOAD};
use crate::listener::{is_unrecoverable_socket_error, spawn_tracked};
use crate::server::handler::DnsRequestHandler;

/// Idle timeout for a DNS/TCP connection: a complete query frame must arrive
/// within this window, otherwise the connection is closed. RFC 7766 §6.2.3
/// leaves the exact value to the server and suggests "a few seconds".
pub(crate) const DNS_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// The DNS/TCP length prefix is 16 bits, so a message cannot exceed 64 KiB.
pub(crate) const DNS_TCP_MAX_MESSAGE_SIZE: usize = u16::MAX as usize;

/// Per-flow cap on concurrently served DNS/TCP connections.
const MAX_IN_FLIGHT_CONNECTIONS: usize = 256;

pub(crate) fn spawn_tcp_listener(
    flow_id: u32,
    listener: TcpListener,
    handler: DnsRequestHandler,
    token: CancellationToken,
    tracker: TaskTracker,
) {
    let serve_tracker = tracker.clone();
    spawn_tracked(&tracker, task_label::task::DNS_LISTENER_SERVE, async move {
        serve(flow_id, listener, handler, token, serve_tracker).await;
    });
}

async fn serve(
    flow_id: u32,
    listener: TcpListener,
    handler: DnsRequestHandler,
    token: CancellationToken,
    tracker: TaskTracker,
) {
    let semaphore = Arc::new(Semaphore::new(MAX_IN_FLIGHT_CONNECTIONS));

    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = token.cancelled() => break,
        };

        let (stream, src) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::debug!("[flow: {flow_id}]: dns/tcp accept error: {e}");
                if is_unrecoverable_socket_error(&e) {
                    token.cancel();
                    break;
                }
                continue;
            }
        };

        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            tracing::trace!("[flow: {flow_id}]: dns/tcp connection overflow, drop {src}");
            continue;
        };

        let handler = handler.clone();
        let token = token.clone();
        spawn_tracked(&tracker, task_label::task::DNS_TCP_CONNECTION, async move {
            let _permit = permit;
            handle_connection(flow_id, stream, src, handler, token).await;
        });
    }

    tracing::info!("[flow: {flow_id}]: dns/tcp listener down");
}

/// Serve one DNS/TCP connection: sequential length-prefixed queries until the
/// peer closes, an idle timeout fires, or the stream is malformed.
///
/// Pipelined queries are buffered implicitly by the socket and answered in
/// order; none of them are rejected (RFC 7766 §6.2.1.1).
async fn handle_connection<S>(
    flow_id: u32,
    mut stream: S,
    src: SocketAddr,
    handler: DnsRequestHandler,
    token: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let frame = tokio::select! {
            _ = token.cancelled() => return,
            result = tokio::time::timeout(DNS_TCP_IDLE_TIMEOUT, read_frame(&mut stream)) => match result {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) => return,
                Ok(Err(e)) => {
                    tracing::debug!("[flow: {flow_id}]: dns/tcp frame from {src} error: {e}");
                    return;
                }
                Err(_) => {
                    tracing::debug!("[flow: {flow_id}]: dns/tcp connection from {src} idle timeout");
                    return;
                }
            },
        };

        let response_bytes = match wire::decode(&frame, src, wire::Protocol::Tcp) {
            wire::DecodeOutcome::Request(request) => {
                let response = handler.handle(&request).await;
                // TCP is not limited by the EDNS UDP payload size: never
                // truncate here, the 16-bit length prefix is the only cap.
                wire::encode_response(&response, MAX_EDNS_PAYLOAD)
            }
            wire::DecodeOutcome::Reply { message, .. } => {
                wire::encode_response(&message, MAX_EDNS_PAYLOAD)
            }
            wire::DecodeOutcome::Ignore | wire::DecodeOutcome::Malformed => {
                // Not a query we can answer (or no usable DNS header): close
                // the connection instead of keeping a bogus exchange alive.
                tracing::debug!("[flow: {flow_id}]: dns/tcp invalid message from {src}");
                return;
            }
        };

        if let Err(e) = write_frame(&mut stream, &response_bytes).await {
            tracing::debug!("[flow: {flow_id}]: dns/tcp response to {src} failed: {e}");
            return;
        }
    }
}

/// Read one length-prefixed DNS message. `Ok(None)` means the peer closed
/// cleanly between messages; a zero-length or truncated frame is an error.
async fn read_frame<S>(stream: &mut S) -> io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 2];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = usize::from(u16::from_be_bytes(len_bytes));
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "zero-length DNS/TCP frame"));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// Write one length-prefixed DNS message (2-byte big-endian length).
async fn write_frame<S>(stream: &mut S, payload: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if payload.len() > DNS_TCP_MAX_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS/TCP response exceeds the 16-bit length prefix",
        ));
    }

    stream.write_all(&(payload.len() as u16).to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
    use tokio::io::duplex;
    use tokio::net::TcpStream;

    use crate::server::handler::tests::{redirect_test_handler, redirect_test_handler_with_addrs};

    use super::*;

    const TEST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    async fn spawn_test_listener() -> (SocketAddr, CancellationToken, TaskTracker) {
        let handler = redirect_test_handler("www.example.com.", TEST_ADDR, 60);
        spawn_test_listener_with_handler(handler).await
    }

    async fn spawn_test_listener_with_handler(
        handler: DnsRequestHandler,
    ) -> (SocketAddr, CancellationToken, TaskTracker) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        spawn_tcp_listener(1, listener, handler, token.clone(), tracker.clone());
        (addr, token, tracker)
    }

    async fn stop(token: CancellationToken, tracker: TaskTracker) {
        token.cancel();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await.unwrap();
    }

    fn query_bytes(id: u16) -> Vec<u8> {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("www.example.com.").unwrap(), RecordType::A));
        query.to_vec().unwrap()
    }

    async fn send_message(stream: &mut TcpStream, payload: &[u8]) {
        stream.write_all(&(payload.len() as u16).to_be_bytes()).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn recv_message(stream: &mut TcpStream) -> Vec<u8> {
        let mut len_bytes = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_bytes))
            .await
            .expect("length prefix within timeout")
            .expect("read length prefix");
        let len = usize::from(u16::from_be_bytes(len_bytes));
        let mut payload = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut payload))
            .await
            .expect("response body within timeout")
            .expect("read response body");
        payload
    }

    async fn expect_server_close(stream: &mut TcpStream) {
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("server closes the connection");
        assert!(matches!(result, Ok(0) | Err(_)), "expected EOF or reset, got {result:?}");
    }

    #[tokio::test]
    async fn answers_query_end_to_end() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        send_message(&mut stream, &query_bytes(0x1234)).await;
        let response = Message::from_vec(&recv_message(&mut stream).await).unwrap();

        assert_eq!(response.id, 0x1234);
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(A(ip)) if *ip == Ipv4Addr::new(192, 0, 2, 1)
        ));

        stop(token, tracker).await;
    }

    /// Two queries on one connection: the second must be answered after the
    /// first, in order (RFC 7766 §6.2.1.1 pipelining support).
    #[tokio::test]
    async fn serves_multiple_queries_on_one_connection() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        for id in [0x0001u16, 0x0002, 0x0003] {
            send_message(&mut stream, &query_bytes(id)).await;
            let response = Message::from_vec(&recv_message(&mut stream).await).unwrap();
            assert_eq!(response.id, id);
            assert_eq!(response.answers.len(), 1);
        }

        stop(token, tracker).await;
    }

    /// Two queries written before reading any response are both answered.
    #[tokio::test]
    async fn answers_pipelined_queries_in_order() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        send_message(&mut stream, &query_bytes(0x0011)).await;
        send_message(&mut stream, &query_bytes(0x0022)).await;

        let first = Message::from_vec(&recv_message(&mut stream).await).unwrap();
        let second = Message::from_vec(&recv_message(&mut stream).await).unwrap();
        assert_eq!(first.id, 0x0011);
        assert_eq!(second.id, 0x0022);

        stop(token, tracker).await;
    }

    #[tokio::test]
    async fn answers_large_response_without_truncation() {
        let addrs: Vec<IpAddr> =
            (1..=40).map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))).collect();
        let handler = redirect_test_handler_with_addrs("www.example.com.", addrs, 60);
        let (addr, token, tracker) = spawn_test_listener_with_handler(handler).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        send_message(&mut stream, &query_bytes(0x7777)).await;
        let payload = recv_message(&mut stream).await;
        assert!(payload.len() > 512, "expected a response larger than the UDP limit");
        let response = Message::from_vec(&payload).unwrap();
        assert_eq!(response.id, 0x7777);
        assert!(!response.metadata.truncation, "TCP responses must not be truncated");
        assert_eq!(response.answers.len(), 40);

        stop(token, tracker).await;
    }

    #[tokio::test]
    async fn closes_idle_connection_after_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let handler = redirect_test_handler("www.example.com.", TEST_ADDR, 60);
        spawn_tcp_listener(1, listener, handler, token.clone(), tracker.clone());

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(
            DNS_TCP_IDLE_TIMEOUT + Duration::from_secs(3),
            stream.read(&mut buf),
        )
        .await
        .expect("idle connection must be closed by the server");
        assert!(matches!(read, Ok(0) | Err(_)));

        stop(token, tracker).await;
    }

    #[tokio::test]
    async fn closes_connection_on_zero_length_frame() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        stream.write_all(&[0x00, 0x00]).await.unwrap();
        expect_server_close(&mut stream).await;

        stop(token, tracker).await;
    }

    #[tokio::test]
    async fn closes_connection_on_malformed_message() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // 11 bytes: not enough for a DNS header, so wire::decode is Malformed.
        send_message(&mut stream, &[0u8; 11]).await;
        expect_server_close(&mut stream).await;

        stop(token, tracker).await;
    }

    #[tokio::test]
    async fn read_frame_returns_none_on_clean_eof() {
        let (mut client, mut server) = duplex(64);
        client.shutdown().await.unwrap();
        assert!(read_frame(&mut server).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_frame_rejects_zero_length_and_truncated_payloads() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x00, 0x00]).await.unwrap();
        assert!(read_frame(&mut server).await.is_err());

        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x00, 0x10, 0x01]).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(read_frame(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn write_frame_uses_big_endian_length_prefix() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"abc").await.unwrap();
        assert_eq!(buffer, vec![0x00, 0x03, b'a', b'b', b'c']);
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let mut buffer = Vec::new();
        let oversized = vec![0u8; DNS_TCP_MAX_MESSAGE_SIZE + 1];
        assert!(write_frame(&mut buffer, &oversized).await.is_err());
    }
}
