use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use landscape_common::concurrency::task_label;

use crate::listener::{is_unrecoverable_socket_error, spawn_tracked, wire};
use crate::server::handler::DnsRequestHandler;

const MAX_IN_FLIGHT: usize = 256;
const READ_BUFFER_SIZE: usize = 4096;

pub(crate) fn spawn_udp_listener(
    flow_id: u32,
    socket: UdpSocket,
    handler: DnsRequestHandler,
    token: CancellationToken,
    tracker: TaskTracker,
) {
    let serve_tracker = tracker.clone();
    spawn_tracked(&tracker, task_label::task::DNS_LISTENER_SERVE, async move {
        serve(flow_id, socket, handler, token, serve_tracker).await;
    });
}

async fn serve(
    flow_id: u32,
    socket: UdpSocket,
    handler: DnsRequestHandler,
    token: CancellationToken,
    tracker: TaskTracker,
) {
    let socket = Arc::new(socket);
    let semaphore = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut buffer = vec![0u8; READ_BUFFER_SIZE];

    loop {
        let (len, src) = tokio::select! {
            result = socket.recv_from(&mut buffer) => match result {
                Ok(received) => received,
                Err(e) => {
                    tracing::debug!("[flow: {flow_id}]: udp recv error: {e}");
                    if is_unrecoverable_socket_error(&e) {
                        token.cancel();
                        break;
                    }
                    continue;
                }
            },
            _ = token.cancelled() => break,
        };

        match wire::decode(&buffer[..len], src, wire::Protocol::Udp) {
            wire::DecodeOutcome::Request(request) => {
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    tracing::trace!("[flow: {flow_id}]: udp query overflow, drop from {src}");
                    continue;
                };
                let socket = Arc::clone(&socket);
                let handler = handler.clone();
                spawn_tracked(&tracker, task_label::task::DNS_QUERY_HANDLE, async move {
                    let _permit = permit;
                    let response = handler.handle(&request).await;
                    let bytes = wire::encode_response(&response, request.edns_max_size);
                    if let Err(e) = socket.send_to(&bytes, request.src).await {
                        tracing::debug!(
                            "[flow: {flow_id}]: udp response to {} failed: {e}",
                            request.src
                        );
                    }
                });
            }
            wire::DecodeOutcome::Reply { message, max_size } => {
                let bytes = wire::encode_response(&message, max_size);
                if let Err(e) = socket.send_to(&bytes, src).await {
                    tracing::debug!("[flow: {flow_id}]: udp reply to {src} failed: {e}");
                }
            }
            wire::DecodeOutcome::Ignore | wire::DecodeOutcome::Malformed => {}
        }
    }

    tracing::info!("[flow: {flow_id}]: udp listener down");
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::Name;
    use hickory_proto::rr::{RData, RecordType, rdata::A};
    use tokio::net::UdpSocket;
    use tokio_util::sync::CancellationToken;
    use tokio_util::task::TaskTracker;

    use crate::server::handler::tests::redirect_test_handler;

    use super::spawn_udp_listener;

    const TEST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    async fn spawn_test_listener() -> (std::net::SocketAddr, CancellationToken, TaskTracker) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let token = CancellationToken::new();
        let tracker = TaskTracker::new();
        let handler = redirect_test_handler("www.example.com.", TEST_ADDR, 60);
        spawn_udp_listener(1, socket, handler, token.clone(), tracker.clone());
        (addr, token, tracker)
    }

    async fn exchange(
        client: &UdpSocket,
        addr: std::net::SocketAddr,
        query: &[u8],
    ) -> Option<Message> {
        client.send_to(query, addr).await.unwrap();
        let mut buffer = vec![0u8; 512];
        let received = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
            .await
            .expect("response within timeout")
            .unwrap();
        Some(Message::from_vec(&buffer[..received.0]).unwrap())
    }

    fn query_bytes(id: u16) -> Vec<u8> {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("www.example.com.").unwrap(), RecordType::A));
        query.to_vec().unwrap()
    }

    #[tokio::test]
    async fn answers_query_end_to_end() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let response = exchange(&client, addr, &query_bytes(0x1234)).await.unwrap();

        assert_eq!(response.id, 0x1234);
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(A(ip)) if *ip == Ipv4Addr::new(192, 0, 2, 1)
        ));

        token.cancel();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await.unwrap();
    }

    #[tokio::test]
    async fn replies_formerr_for_malformed_query_with_header() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let malformed = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let response = exchange(&client, addr, &malformed).await.unwrap();

        assert_eq!(response.id, 0x1234);
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.response_code, ResponseCode::FormErr);
        assert!(response.queries.is_empty());

        token.cancel();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await.unwrap();
    }

    #[tokio::test]
    async fn drops_garbage_without_header() {
        let (addr, token, tracker) = spawn_test_listener().await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client.send_to(&[0; 11], addr).await.unwrap();
        let mut buffer = vec![0u8; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut buffer))
                .await
                .is_err()
        );

        token.cancel();
        tracker.close();
        tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await.unwrap();
    }
}
