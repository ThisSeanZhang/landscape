use std::{io, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use hickory_proto::{
    op::{Header, Metadata, ResponseCode},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use hickory_server::{
    net::xfer::Protocol,
    server::{Request, RequestHandler},
};
use http::{Request as HttpRequest, StatusCode};
use rustls::{crypto::CryptoProvider, server::ResolvesServerCert, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::{listener::DohTimeouts, server::handler::DnsRequestHandler};

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
) {
    let tls_acceptor = match build_tls_acceptor(config.server_cert_resolver.clone()) {
        Ok(acceptor) => acceptor,
        Err(e) => {
            tracing::error!("[flow: {flow_id}]: create DoH TLS acceptor error: {e}");
            return;
        }
    };

    tokio::spawn(async move {
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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
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
    match Request::from_bytes(message_bytes.to_vec(), src_addr, Protocol::Https) {
        Ok(request) => {
            if request.metadata.message_type == hickory_proto::op::MessageType::Response {
                return;
            }
            handler
                .handle_request::<_, hickory_server::net::runtime::TokioTime>(
                    &request,
                    response_handle,
                )
                .await;
        }
        Err(e) => {
            tracing::debug!("failed to parse DoH DNS message from {src_addr}: {e}");
            respond_to_invalid_dns_message(message_bytes, response_handle).await;
        }
    }
}

async fn respond_to_invalid_dns_message(message_bytes: &[u8], response_handle: DohResponseHandle) {
    if let Some(buffer) = formerr_response(message_bytes) {
        let _ = response_handle.send_dns_message(buffer).await;
    } else {
        let _ = response_handle
            .send_http_error(StatusCode::BAD_REQUEST, "invalid DNS wire message")
            .await;
    }
}

fn formerr_response(message_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = BinDecoder::new(message_bytes);
    let header = Header::read(&mut decoder).ok()?;
    let mut response_metadata = Metadata::response_from_request(&header.metadata);
    response_metadata.response_code = ResponseCode::FormErr;
    let response_header = Header {
        metadata: response_metadata,
        counts: Default::default(),
    };
    let mut buffer = Vec::with_capacity(12); // DNS header is always 12 bytes
    let mut encoder = BinEncoder::new(&mut buffer);
    response_header.emit(&mut encoder).ok()?;
    Some(buffer)
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

fn is_unrecoverable_socket_error(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::NotConnected | io::ErrorKind::ConnectionAborted)
}

fn reap_tasks<T: 'static>(tasks: &mut JoinSet<T>) {
    while tasks.try_join_next().is_some() {}
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Header, MessageType, ResponseCode};
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

    use super::formerr_response;

    #[test]
    fn invalid_dns_with_header_returns_formerr_wire_response() {
        let request = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

        let response = formerr_response(&request).unwrap();
        let mut decoder = BinDecoder::new(&response);
        let header = Header::read(&mut decoder).unwrap();

        assert_eq!(header.id, 0x1234);
        assert_eq!(header.message_type, MessageType::Response);
        assert_eq!(header.response_code, ResponseCode::FormErr);
    }

    #[test]
    fn invalid_dns_without_header_has_no_wire_response() {
        assert!(formerr_response(&[0; 11]).is_none());
    }
}
