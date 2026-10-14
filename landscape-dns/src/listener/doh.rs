use std::{io, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{Request as HttpRequest, StatusCode};
use rustls::{ServerConfig, crypto::CryptoProvider, server::ResolvesServerCert};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::listener::is_unrecoverable_socket_error;
use crate::listener::spawn_tracked;
use crate::listener::wire::{self, Protocol};
use crate::{listener::DohTimeouts, server::handler::DnsRequestHandler};
use landscape_common::concurrency::task_label;
use tokio_util::task::TaskTracker;

mod request;
mod response;

use request::extract_doh_message;
use response::DohResponseHandle;

pub(super) const MIME_APPLICATION_DNS: &str = "application/dns-message";
pub(super) const MAX_DNS_MESSAGE_SIZE: usize = 65_535;
const MAX_CONCURRENT_DOH_STREAMS: u32 = 128;

#[derive(Clone)]
pub(crate) struct DohListenerConfig {
    pub(crate) timeouts: DohTimeouts,
    pub(crate) server_cert_resolver: Arc<dyn ResolvesServerCert>,
    pub(crate) dns_hostname: Option<String>,
    pub(crate) http_endpoint: String,
}

pub(crate) fn spawn_doh_listener(
    flow_id: u32,
    listener: TcpListener,
    config: DohListenerConfig,
    handler: DnsRequestHandler,
    shutdown: CancellationToken,
    tracker: TaskTracker,
) {
    let tls_acceptor = match build_tls_acceptor(config.server_cert_resolver.clone()) {
        Ok(acceptor) => acceptor,
        Err(e) => {
            tracing::error!("[flow: {flow_id}]: create DoH TLS acceptor error: {e}");
            return;
        }
    };

    spawn_tracked(&tracker, task_label::task::DNS_DOH_HANDLER, async move {
        let handler = Arc::new(handler);
        let mut connection_tasks = JoinSet::new();
        loop {
            reap_tasks(&mut connection_tasks);
            let has_connection_tasks = !connection_tasks.is_empty();
            let (tcp_stream, src_addr) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        tracing::debug!("[flow: {flow_id}]: accept DoH connection error: {e}");
                        if is_unrecoverable_socket_error(&e) {
                            // 同生共死:DoH 监听不可恢复错误取消整个 flow
                            // token(UDP 一并退出),由上层 refresh 整体重建
                            shutdown.cancel();
                            break;
                        }
                        continue;
                    }
                },
                joined = connection_tasks.join_next(), if has_connection_tasks => {
                    if let Some(Err(e)) = joined {
                        tracing::debug!("[flow: {flow_id}]: DoH connection task failed: {e}");
                    }
                    continue;
                },
                _ = shutdown.cancelled() => break,
            };

            if let Err(e) = sanitize_src_address(src_addr) {
                tracing::warn!(
                    "[flow: {flow_id}]: DoH address can not be responded to {src_addr}: {e}"
                );
                continue;
            }

            let tls_acceptor = tls_acceptor.clone();
            let handler = handler.clone();
            let config = config.clone();
            let shutdown = shutdown.clone();
            connection_tasks.spawn(async move {
                handle_doh_connection(
                    flow_id,
                    tcp_stream,
                    src_addr,
                    tls_acceptor,
                    config,
                    handler,
                    shutdown,
                )
                .await;
            });
        }
        connection_tasks.abort_all();
        while connection_tasks.join_next().await.is_some() {}
        tracing::info!("[flow: {flow_id}]: DoH listener down");
    });
}

fn build_tls_acceptor(
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<TlsAcceptor> {
    let provider = CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_cert_resolver(server_cert_resolver);
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn h2_server_handshake<T>(io: T) -> h2::server::Handshake<T, Bytes>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    h2::server::Builder::new().max_concurrent_streams(MAX_CONCURRENT_DOH_STREAMS).handshake(io)
}

async fn handle_doh_connection(
    flow_id: u32,
    tcp_stream: TcpStream,
    src_addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    config: DohListenerConfig,
    handler: Arc<DnsRequestHandler>,
    shutdown: CancellationToken,
) {
    let tls_stream = match tokio::time::timeout(
        config.timeouts.handshake,
        tls_acceptor.accept(tcp_stream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::debug!("[flow: {flow_id}]: DoH TLS handshake from {src_addr} error: {e}");
            return;
        }
        Err(_) => {
            tracing::warn!("[flow: {flow_id}]: DoH TLS handshake timeout from {src_addr}");
            return;
        }
    };

    let mut h2 = match tokio::time::timeout(
        config.timeouts.handshake,
        h2_server_handshake(tls_stream),
    )
    .await
    {
        Ok(Ok(h2)) => h2,
        Ok(Err(e)) => {
            tracing::warn!("[flow: {flow_id}]: DoH HTTP/2 handshake from {src_addr} error: {e}");
            return;
        }
        Err(_) => {
            tracing::warn!("[flow: {flow_id}]: DoH HTTP/2 handshake timeout from {src_addr}");
            return;
        }
    };

    let mut request_tasks = JoinSet::new();
    loop {
        reap_tasks(&mut request_tasks);
        let has_request_tasks = !request_tasks.is_empty();
        let (request, respond) = tokio::select! {
            accepted = h2.accept() => match accepted {
                Some(Ok(request)) => request,
                Some(Err(e)) => {
                    tracing::debug!("[flow: {flow_id}]: DoH HTTP/2 request from {src_addr} error: {e}");
                    return;
                }
                None => return,
            },
            joined = request_tasks.join_next(), if has_request_tasks => {
                if let Some(Err(e)) = joined {
                    tracing::debug!("[flow: {flow_id}]: DoH request task failed from {src_addr}: {e}");
                }
                continue;
            },
            _ = tokio::time::sleep(config.timeouts.idle_connection), if !has_request_tasks => {
                tracing::debug!("[flow: {flow_id}]: idle DoH HTTP/2 connection from {src_addr} timed out");
                return;
            },
            _ = shutdown.cancelled() => {
                request_tasks.abort_all();
                return;
            },
        };

        let handler = handler.clone();
        let config = config.clone();
        request_tasks.spawn(async move {
            handle_h2_request(flow_id, src_addr, request, respond, config, handler).await;
        });
    }
}

async fn handle_h2_request(
    flow_id: u32,
    src_addr: SocketAddr,
    request: HttpRequest<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    config: DohListenerConfig,
    handler: Arc<DnsRequestHandler>,
) {
    let endpoint = Arc::<str>::from(config.http_endpoint.clone());
    let response_handle = DohResponseHandle::new(respond, endpoint);
    let message_bytes = match extract_doh_message(
        config.dns_hostname.as_deref(),
        &config.http_endpoint,
        request,
        config.timeouts.request_body,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::debug!("[flow: {flow_id}]: invalid DoH request from {src_addr}: {e}");
            let _ = response_handle.send_http_error(e.status(), e.message()).await;
            return;
        }
    };

    handle_dns_message(message_bytes.as_ref(), src_addr, handler, response_handle).await;
}

async fn handle_dns_message(
    message_bytes: &[u8],
    src_addr: SocketAddr,
    handler: Arc<DnsRequestHandler>,
    response_handle: DohResponseHandle,
) {
    match wire::decode(message_bytes, src_addr, Protocol::Https) {
        wire::DecodeOutcome::Request(request) => {
            let response = handler.handle(&request).await;
            let buffer = wire::encode_response(&response, u16::MAX);
            if let Err(e) = response_handle.send_dns_message(buffer).await {
                tracing::debug!("DoH response to {src_addr} failed: {e}");
            }
        }
        wire::DecodeOutcome::Reply { message, max_size } => {
            let buffer = wire::encode_response(&message, max_size);
            if let Err(e) = response_handle.send_dns_message(buffer).await {
                tracing::debug!("DoH reply to {src_addr} failed: {e}");
            }
        }
        wire::DecodeOutcome::Malformed => {
            if let Err(e) = response_handle
                .send_http_error(StatusCode::BAD_REQUEST, "invalid DNS wire message")
                .await
            {
                tracing::debug!("DoH bad request response to {src_addr} failed: {e}");
            }
        }
        wire::DecodeOutcome::Ignore => {
            if let Err(e) = response_handle
                .send_http_error(StatusCode::BAD_REQUEST, "DNS message was not a query")
                .await
            {
                tracing::debug!("DoH non-query rejection to {src_addr} failed: {e}");
            }
        }
    }
}

fn sanitize_src_address(src: SocketAddr) -> Result<(), String> {
    if src.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {src}"));
    }
    if src.ip().is_unspecified() {
        return Err(format!("cannot respond to unspecified addr: {src}"));
    }
    Ok(())
}

fn reap_tasks<T: 'static>(tasks: &mut JoinSet<T>) {
    while tasks.try_join_next().is_some() {}
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
    use http::header;
    use rustls::server::ResolvesServerCert;

    use crate::listener::DohTimeouts;
    use crate::server::handler::DnsRequestHandler;
    use crate::server::handler::tests::redirect_test_handler;

    use super::{DohListenerConfig, MIME_APPLICATION_DNS, sanitize_src_address};

    const TEST_SRC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5300);
    const TEST_ANSWER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    #[derive(Debug)]
    struct NoCertResolver;

    impl ResolvesServerCert for NoCertResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello,
        ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    fn test_config() -> DohListenerConfig {
        DohListenerConfig {
            timeouts: DohTimeouts::default(),
            server_cert_resolver: std::sync::Arc::new(NoCertResolver),
            dns_hostname: None,
            http_endpoint: "/dns-query".to_string(),
        }
    }

    async fn doh_exchange(
        body: Bytes,
        handler: std::sync::Arc<DnsRequestHandler>,
    ) -> (http::StatusCode, Vec<u8>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Serve requests until the client closes the connection: dropping the
        // socket right after responding would RST and destroy the response.
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut server = super::h2_server_handshake(stream).await.unwrap();
            while let Some(accepted) = server.accept().await {
                let (request, respond) = accepted.unwrap();
                super::handle_h2_request(
                    1,
                    TEST_SRC,
                    request,
                    respond,
                    test_config(),
                    handler.clone(),
                )
                .await;
            }
        });

        let client_io = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = http::Request::post("https://dns.local/dns-query")
            .header(header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .body(())
            .unwrap();
        let (response_fut, mut send_body) = send_request.send_request(request, false).unwrap();
        send_body.send_data(body, true).unwrap();

        let response = response_fut.await.unwrap();
        let status = response.status();
        let mut body_stream = response.into_body();
        let mut received = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let chunk = chunk.unwrap();
            let len = chunk.len();
            received.extend_from_slice(&chunk);
            let _ = body_stream.flow_control().release_capacity(len);
        }
        drop(send_body);
        drop(send_request);
        drop(body_stream);
        server_task.await.unwrap();
        (status, received)
    }

    fn query_bytes(id: u16) -> Vec<u8> {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("www.example.com.").unwrap(), RecordType::A));
        query.to_vec().unwrap()
    }

    fn response_bytes(id: u16) -> Vec<u8> {
        Message::new(id, MessageType::Response, OpCode::Query).to_vec().unwrap()
    }

    #[tokio::test]
    async fn resolves_doh_post_query_end_to_end() {
        let handler =
            std::sync::Arc::new(redirect_test_handler("www.example.com.", TEST_ANSWER, 60));

        let (status, body) = doh_exchange(Bytes::from(query_bytes(0x1234)), handler).await;

        assert_eq!(status, http::StatusCode::OK);
        let response = Message::from_vec(&body).unwrap();
        assert_eq!(response.id, 0x1234);
        assert_eq!(response.response_code, hickory_proto::op::ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert!(matches!(
            &response.answers[0].data,
            RData::A(A(ip)) if *ip == Ipv4Addr::new(192, 0, 2, 1)
        ));
    }

    #[tokio::test]
    async fn malformed_body_answers_http_400() {
        let handler =
            std::sync::Arc::new(redirect_test_handler("www.example.com.", TEST_ANSWER, 60));

        let (status, body) = doh_exchange(Bytes::from(vec![0; 11]), handler).await;

        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("invalid DNS wire message"));
    }

    #[tokio::test]
    async fn answers_http_400_for_response_type_body() {
        let handler =
            std::sync::Arc::new(redirect_test_handler("www.example.com.", TEST_ANSWER, 60));

        let (status, body) = doh_exchange(Bytes::from(response_bytes(0x4321)), handler).await;

        assert_eq!(status, http::StatusCode::BAD_REQUEST);
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("DNS message was not a query"));
    }

    #[test]
    fn rejects_port_zero_and_unspecified_sources() {
        assert!(sanitize_src_address("192.168.1.1:0".parse().unwrap()).is_err());
        assert!(sanitize_src_address("0.0.0.0:53".parse().unwrap()).is_err());
        assert!(sanitize_src_address("192.168.1.1:5300".parse().unwrap()).is_ok());
    }
}
