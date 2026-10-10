//! Self-managed DNS-over-HTTPS (RFC 8484): one long-lived HTTP/2 connection
//! carrying one POST exchange per query. HTTP correlates the request and
//! response, so per §4.1 the wire ID is zeroed for cache friendliness and
//! the response ID passes through as received. The client configuration
//! mirrors the legacy dial: the resolver's TLS config with the "h2" ALPN.
//! Liveness is a direct fact: the h2 driver task completes the moment the
//! connection goes away (GOAWAY, reset or I/O failure), so `is_alive` reads
//! the driver's join handle — no separate watcher task.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use hickory_proto::ProtoError;
use hickory_proto::op::DnsResponse;
use hickory_resolver::net::NetError;
use http::{Method, Request, Uri, Version, header};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::exp_conn_pool::allowance::TimeAllowance;
use crate::exp_conn_pool::transport::DialParams;
use crate::exp_conn_pool::transport::WireQuery;
use crate::exp_conn_pool::transport::stream::connect_marked_tcp;

// RFC 8484 §5.1: the only defined request/response media type.
const MIME_APPLICATION_DNS: &str = "application/dns-message";

// RFC 8484 §6 limits one DNS message to 65535 bytes, the same bound
// hickory's own `fetch_body` enforces.
const MAX_BODY: usize = u16::MAX as usize;

pub(crate) fn doh_client_config(mut base: ClientConfig) -> Arc<ClientConfig> {
    base.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(base)
}

pub(crate) async fn connect_doh(
    addr: SocketAddr,
    server_name: String,
    path: Arc<str>,
    config: Arc<ClientConfig>,
    dial: DialParams,
    allowance: TimeAllowance,
) -> Result<DohH2Connection, NetError> {
    let uri = build_uri(&server_name, &path)?;
    let server_name = ServerName::try_from(server_name)
        .map_err(|_| NetError::from("invalid HTTPS server name"))?;

    let tcp = connect_marked_tcp(addr, dial, allowance).await?;
    let tls =
        allowance.complete_within(TlsConnector::from(config).connect(server_name, tcp)).await??;

    let mut builder = h2::client::Builder::new();
    // DNS exchanges never use server push.
    builder.enable_push(false);
    let (h2, driver) = allowance.complete_within(builder.handshake(tls)).await??;

    // The driver future must be polled for the h2 connection to make
    // progress; its join handle doubles as the liveness signal.
    let _driver = tokio::spawn(async move {
        let _ = driver.await;
    });

    Ok(DohH2Connection { h2, uri, _driver })
}

// `https://{server_name}{path}`, tolerating a path without the leading slash.
fn build_uri(server_name: &str, path: &str) -> Result<Uri, NetError> {
    let mut uri = String::with_capacity(server_name.len() + path.len() + "https://".len() + 1);
    uri.push_str("https://");
    uri.push_str(server_name);
    if !path.starts_with('/') {
        uri.push('/');
    }
    uri.push_str(path);
    uri.parse().map_err(|_| NetError::from("invalid DoH endpoint URI"))
}

pub(crate) struct DohH2Connection {
    h2: h2::client::SendRequest<Bytes>,
    uri: Uri,
    // Polled until the h2 connection ends; `is_finished` is the liveness
    // signal and aborting it tears the connection down.
    _driver: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for DohH2Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohH2Connection").field("closed", &self._driver.is_finished()).finish()
    }
}

impl DohH2Connection {
    pub(crate) async fn query(&self, query: WireQuery) -> Result<DnsResponse, NetError> {
        let h2 = self.h2.clone();
        let uri = self.uri.clone();
        // RFC 8484 §4.1: a DoH client SHOULD use a DNS ID of 0, since HTTP
        // itself correlates the request and response; the response ID is
        // passed through as received. Zero the two header bytes without
        // re-encoding; the common all-zero case is sent as-is (zero copy).
        let wire = query.wire;
        let body = if wire[0] == 0 && wire[1] == 0 {
            wire
        } else {
            let mut zeroed = BytesMut::with_capacity(wire.len());
            zeroed.extend_from_slice(&[0, 0]);
            zeroed.extend_from_slice(&wire[2..]);
            zeroed.freeze()
        };
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri(uri)
            .header(header::CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(header::ACCEPT, MIME_APPLICATION_DNS)
            .header(header::CONTENT_LENGTH, body.len())
            .body(())
            .map_err(|e| NetError::from(format!("invalid DoH request: {e}")))?;

        let mut h2 = h2.ready().await.map_err(NetError::from)?;
        let (response, mut send) = h2.send_request(request, false).map_err(NetError::from)?;
        send.send_data(body, true).map_err(NetError::from)?;
        let response = response.await.map_err(NetError::from)?;

        if !response.status().is_success() {
            // An HTTP status answer says the server (and the connection)
            // are healthy — the failure belongs to this query. The
            // message-level error keeps the detail and does not retire a
            // working connection over a 4xx/5xx.
            return Err(NetError::from(ProtoError::Msg(format!(
                "DoH upstream answered HTTP status {}",
                response.status()
            ))));
        }
        // RFC 8484 §5.1: an absent Content-Type means the standard media
        // type, mirroring the legacy dial path.
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(MIME_APPLICATION_DNS);
        if content_type != MIME_APPLICATION_DNS {
            return Err(NetError::from(ProtoError::Msg(format!(
                "DoH content type unsupported: {content_type}"
            ))));
        }
        let content_length = match response.headers().get(header::CONTENT_LENGTH) {
            Some(value) => value.to_str().ok().and_then(|raw| raw.parse::<usize>().ok()),
            None => None,
        };

        let mut body = response.into_body();
        let mut buf = Vec::with_capacity(512);
        loop {
            match futures_util::StreamExt::next(&mut body).await {
                Some(Ok(frame)) => {
                    // Return the frame's flow-control window before
                    // anything else: h2 releases delivered data only
                    // explicitly, and an unreleased window permanently
                    // shrinks the connection's — it deadlocks once the
                    // debt reaches the initial 64 KiB.
                    if let Err(e) = body.flow_control().release_capacity(frame.len()) {
                        return Err(NetError::from(e));
                    }
                    if buf.len() + frame.len() > MAX_BODY {
                        return Err(NetError::RequestTooLarge);
                    }
                    buf.extend_from_slice(&frame);
                }
                Some(Err(e)) => return Err(NetError::from(e)),
                None => break,
            }
        }
        if let Some(expected) = content_length
            && buf.len() != expected
        {
            return Err(NetError::from("DoH body does not match content-length"));
        }

        DnsResponse::from_buffer(buf).map_err(NetError::from)
    }

    pub(crate) fn is_alive(&self) -> bool {
        !self._driver.is_finished()
    }

    pub(crate) fn close(&self) {
        // h2 has no client-side GOAWAY; aborting the driver tears the
        // connection down promptly instead of waiting for refcounts.
        self._driver.abort();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::StreamExt;
    use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_resolver::net::NetError;
    use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ClientConfig, RootCertStore};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::DialParams;
    use crate::exp_conn_pool::allowance::TimeAllowance;
    use crate::exp_conn_pool::transport::wire_query;

    const SERVER_NAME: &str = "dns.example";
    const QUERY_PATH: &str = "/dns-query";

    fn localhost_dial() -> DialParams {
        DialParams { mark_value: 0, bind_addr4: None, bind_addr6: None }
    }

    fn query(name: &str) -> DnsRequest {
        let query = Query::query(Name::parse(name, None).unwrap(), RecordType::A);
        DnsRequest::from_query(query, DnsRequestOptions::default())
    }

    // Explicit crypto provider: nothing installs a process-level default,
    // and tests must not depend on crate features enabled elsewhere.
    fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn test_cert() -> (rustls::ServerConfig, ClientConfig) {
        let certified = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap(),
            )
            .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];

        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client = ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server, client)
    }

    // What the upstream observed about one request, for wire compliance
    // assertions.
    #[derive(Debug, PartialEq, Eq, Clone)]
    struct SeenRequest {
        method: String,
        path: String,
        content_type: String,
        body_len: usize,
        // DNS message ID as seen on the wire.
        id: u16,
    }

    // DoH echo upstream: answers each POST with a DNS response echoing the
    // request message (ID included). Records what each request looked like.
    async fn spawn_doh_echo_upstream()
    -> (std::net::SocketAddr, ClientConfig, Arc<Mutex<Vec<SeenRequest>>>) {
        let (server_config, client_config) = test_cert();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let seen: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_handle = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let Ok(tls) = acceptor.accept(stream).await else { continue };
                let Ok(mut connection) = h2::server::Builder::new().handshake(tls).await else {
                    continue;
                };
                let seen_handle = seen_handle.clone();
                tokio::spawn(async move {
                    while let Some(request) = connection.next().await {
                        let Ok((request, mut respond)) = request else { break };
                        let seen_handle = seen_handle.clone();
                        tokio::spawn(async move {
                            let (parts, mut body) = request.into_parts();
                            let mut buf = Vec::new();
                            while let Some(Ok(chunk)) = body.next().await {
                                buf.extend_from_slice(&chunk);
                            }
                            let mut message = Message::from_vec(&buf).expect("request decodes");
                            seen_handle.lock().unwrap().push(SeenRequest {
                                method: parts.method.as_str().to_string(),
                                path: parts.uri.path().to_string(),
                                content_type: parts
                                    .headers
                                    .get(CONTENT_TYPE)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or_default()
                                    .to_string(),
                                body_len: buf.len(),
                                id: message.metadata.id,
                            });
                            message.metadata.message_type = MessageType::Response;
                            let payload = message.to_vec().unwrap();
                            let response = http::Response::builder()
                                .status(200)
                                .header(CONTENT_TYPE, "application/dns-message")
                                .header(CONTENT_LENGTH, payload.len())
                                .body(())
                                .unwrap();
                            let mut send = respond.send_response(response, false).unwrap();
                            send.send_data(Bytes::from(payload), true).unwrap();
                        });
                    }
                });
            }
        });
        (addr, client_config, seen)
    }

    async fn connect_local(
        addr: std::net::SocketAddr,
        client_config: ClientConfig,
        allowance: TimeAllowance,
    ) -> Result<super::DohH2Connection, NetError> {
        super::connect_doh(
            addr,
            SERVER_NAME.to_string(),
            Arc::from(QUERY_PATH),
            super::doh_client_config(client_config),
            localhost_dial(),
            allowance,
        )
        .await
    }

    #[tokio::test]
    async fn round_trip_over_doh() {
        let (addr, client_config, seen) = spawn_doh_echo_upstream().await;
        let conn = connect_local(addr, client_config, TimeAllowance::new(Duration::from_secs(2)))
            .await
            .unwrap();
        assert!(conn.is_alive());

        let request = query("example.com.");
        let response = conn.query(wire_query(request)).await.unwrap();
        // RFC 8484 §4.1: the wire ID is 0 and the response ID passes
        // through as received (the echo upstream answers with 0).
        assert_eq!(response.metadata.id, 0);
        assert_eq!(response.metadata.message_type, MessageType::Response);

        // Wire compliance: POST, configured path, DNS media type, zero ID.
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, QUERY_PATH);
        assert_eq!(seen[0].content_type, "application/dns-message");
        assert!(seen[0].body_len > 0);
        assert_eq!(seen[0].id, 0, "RFC 8484 §4.1: DoH clients SHOULD send DNS ID 0");
    }

    #[tokio::test]
    async fn http_status_error_keeps_connection() {
        // Always answers 503: the query fails but the connection itself
        // stays healthy and keeps accepting queries.
        let (server_config, client_config) = test_cert();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let Ok(tls) = acceptor.accept(stream).await else { continue };
                let Ok(mut connection) = h2::server::Builder::new().handshake(tls).await else {
                    continue;
                };
                tokio::spawn(async move {
                    while let Some(request) = connection.next().await {
                        let Ok((request, mut respond)) = request else { break };
                        tokio::spawn(async move {
                            let (_, mut body) = request.into_parts();
                            while let Some(Ok(_)) = body.next().await {}
                            let response = http::Response::builder().status(503).body(()).unwrap();
                            let mut send = respond.send_response(response, false).unwrap();
                            send.send_data(Bytes::from_static(b"unavailable"), true).unwrap();
                        });
                    }
                });
            }
        });

        let conn = connect_local(addr, client_config, TimeAllowance::new(Duration::from_secs(2)))
            .await
            .unwrap();

        for _ in 0..2 {
            let error = conn.query(wire_query(query("example.com."))).await.unwrap_err();
            // Message-classified: an HTTP status answer must not retire
            // the connection.
            assert!(
                matches!(error, NetError::Proto(hickory_proto::ProtoError::Msg(_))),
                "unexpected error: {error:?}"
            );
        }
        assert!(conn.is_alive());
    }

    #[tokio::test]
    async fn oversized_body_keeps_connection() {
        // The first response carries a body past the RFC 8484 §6 message
        // cap; the query fails as a message-level error and the
        // connection keeps serving the next query.
        let (server_config, client_config) = test_cert();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served_oversized = Arc::new(AtomicUsize::new(0));
        tokio::spawn({
            let served_oversized = served_oversized.clone();
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { break };
                    let Ok(tls) = acceptor.accept(stream).await else { continue };
                    let Ok(mut connection) =
                        h2::server::Builder::new().handshake::<_, Bytes>(tls).await
                    else {
                        continue;
                    };
                    let served_oversized = served_oversized.clone();
                    tokio::spawn(async move {
                        while let Some(request) = connection.next().await {
                            let Ok((request, mut respond)) = request else { break };
                            let served_oversized = served_oversized.clone();
                            tokio::spawn(async move {
                                let (_, mut body) = request.into_parts();
                                let mut msg_buf = Vec::new();
                                while let Some(Ok(chunk)) = body.next().await {
                                    msg_buf.extend_from_slice(&chunk);
                                }
                                if served_oversized.fetch_add(1, Ordering::SeqCst) == 0 {
                                    let response = http::Response::builder()
                                        .status(200)
                                        .header(CONTENT_TYPE, "application/dns-message")
                                        .header(CONTENT_LENGTH, super::MAX_BODY + 1)
                                        .body(())
                                        .unwrap();
                                    let Ok(mut send) = respond.send_response(response, false)
                                    else {
                                        return;
                                    };
                                    // The client abandons the stream once the cap
                                    // is crossed, so a reset mid-body is expected.
                                    let _ = send.send_data(
                                        Bytes::from(vec![0u8; super::MAX_BODY + 1]),
                                        true,
                                    );
                                    return;
                                }
                                let mut message =
                                    Message::from_vec(&msg_buf).expect("request decodes");
                                message.metadata.message_type = MessageType::Response;
                                let payload = message.to_vec().unwrap();
                                let response = http::Response::builder()
                                    .status(200)
                                    .header(CONTENT_TYPE, "application/dns-message")
                                    .header(CONTENT_LENGTH, payload.len())
                                    .body(())
                                    .unwrap();
                                let Ok(mut send) = respond.send_response(response, false) else {
                                    return;
                                };
                                let _ = send.send_data(Bytes::from(payload), true);
                            });
                        }
                    });
                }
            }
        });

        let conn = connect_local(addr, client_config, TimeAllowance::new(Duration::from_secs(2)))
            .await
            .unwrap();

        let error = conn.query(wire_query(query("big.example."))).await.unwrap_err();
        assert!(matches!(error, NetError::RequestTooLarge));
        assert!(conn.is_alive(), "an oversized body must not retire the connection");

        let request = query("example.com.");
        let response = conn.query(wire_query(request)).await.unwrap();
        // The wire ID is 0 (RFC 8484 §4.1) and passes through as received.
        assert_eq!(response.metadata.id, 0);
        assert_eq!(response.metadata.message_type, MessageType::Response);
    }

    #[tokio::test]
    async fn peer_close_fails_pending_and_marks_dead() {
        // Completes the handshakes, reads one request, then goes away
        // while the client still waits for its answer.
        let (server_config, client_config) = test_cert();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            let mut connection =
                h2::server::Builder::new().handshake::<_, Bytes>(tls).await.unwrap();
            let Some(Ok((_request, _respond))) = connection.next().await else { return };
            // Drop everything without answering: the abrupt teardown must
            // surface as a closed connection on the client side.
        });

        let conn = connect_local(addr, client_config, TimeAllowance::new(Duration::from_secs(2)))
            .await
            .unwrap();
        let error = conn.query(wire_query(query("example.com."))).await.unwrap_err();
        // A closed peer must surface as connection-closed so the scheduler
        // can transparently redial.
        assert!(error.is_connection_closed(), "unexpected error: {error:?}");
        assert!(!conn.is_alive());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_failure_surfaces_as_error() {
        // A plain-TCP listener that never answers the TLS handshake: the
        // allowance must turn it into a timeout, not a hang.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let (_server_config, client_config) = test_cert();

        let error =
            connect_local(addr, client_config, TimeAllowance::new(Duration::from_millis(200)))
                .await
                .unwrap_err();
        assert!(matches!(error, NetError::Timeout));
    }
}
