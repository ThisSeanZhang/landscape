//! Native DoH (DNS-over-HTTPS, RFC 8484) transport.
//!
//! One h2 connection, one HTTP/2 stream per query (message id 0 — the HTTP
//! mapping correlates the transaction). Mirrors hickory-net's `h2.rs`
//! semantics: POST to the query path, `application/dns-message`, response
//! status must be 2xx, the Content-Type (when present) must be the DNS wire
//! format, and the body length must match Content-Length when advertised.
//! Unlike hickory-net, the whole exchange is bounded by the pool's
//! `query_timeout` (hickory's DoH path had no transport-level timeout).

use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use h2::client::SendRequest;
use hickory_proto::op::{DnsRequestOptions, Message, MessageType, Query};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Response, Version};
use tokio::sync::Semaphore;

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::upstream::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

use super::{build_message, classify_message};

const MIME_APPLICATION_DNS: &str = "application/dns-message";
const ALPN_H2: &[u8] = b"h2";

/// Dial-and-forget h2 connection driver; `SendRequest` clones share it.
pub(crate) struct DohConnector {
    pub(super) addr: SocketAddr,
    pub(super) server_name: Arc<str>,
    pub(super) path: Arc<str>,
    pub(super) tls_config: Arc<rustls::ClientConfig>,
    pub(super) provider: MarkRuntimeProvider,
    pub(super) connect_timeout: Duration,
    pub(super) query_timeout: Duration,
    pub(super) max_active_requests: usize,
}

impl Debug for DohConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohConnector")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .field("path", &self.path)
            .finish()
    }
}

#[async_trait]
impl DnsConnector for DohConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        // DoH must negotiate h2 over TLS (RFC 8484 §4.1).
        let mut config = (*self.tls_config).clone();
        if config.alpn_protocols.is_empty() {
            config.alpn_protocols = vec![ALPN_H2.to_vec()];
        }
        let stream = super::tls::connect_tls(
            &self.provider,
            self.addr,
            &self.server_name,
            Arc::new(config),
            self.connect_timeout,
        )
        .await?;

        let mut builder = h2::client::Builder::new();
        builder.enable_push(false);
        let (send_request, connection) = builder
            .handshake(stream)
            .await
            .map_err(|e| DnsConnError::Io(format!("h2 handshake failed: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!("DoH h2 connection failed: {e}");
            }
        });

        Ok(Arc::new(DohConn {
            h2: send_request,
            server_name: self.server_name.clone(),
            path: self.path.clone(),
            port: self.addr.port(),
            query_timeout: self.query_timeout,
            ip: self.addr.ip(),
            cap: Arc::new(Semaphore::new(self.max_active_requests.max(1))),
            in_flight: AtomicUsize::new(0),
        }))
    }

    fn transport(&self) -> DnsTransport {
        DnsTransport::Stream
    }

    fn ip(&self) -> IpAddr {
        self.addr.ip()
    }

    /// Test-only endpoint introspection (topology assertions).
    #[cfg(test)]
    fn test_endpoint(&self) -> Option<(SocketAddr, String)> {
        Some((self.addr, "Https".to_string()))
    }

    /// Test-only TLS config introspection.
    #[cfg(test)]
    fn test_tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        Some(self.tls_config.clone())
    }
}

/// One established DoH connection (a cloneable h2 handle).
struct DohConn {
    h2: SendRequest<Bytes>,
    server_name: Arc<str>,
    path: Arc<str>,
    /// The upstream's port, for the `:port` authority component of the
    /// request URI (virtual-host routing on non-default ports).
    port: u16,
    query_timeout: Duration,
    ip: IpAddr,
    /// Client-side in-flight cap. Saturation must surface as the capacity
    /// class (`NoConnections`) exactly like the stream multiplexer: a
    /// silently queued `h2.ready()` / `send_request` would instead age into
    /// a spurious `Timeout`, which the pool counts against the upstream's
    /// health — a healthy upstream under burst load would flip offline.
    cap: Arc<Semaphore>,
    /// Queries currently holding a permit. Paired with the peer's advertised
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (see [`DohConn::query`]): the
    /// semaphore alone cannot see a peer limit below our own cap.
    in_flight: AtomicUsize,
}

impl Debug for DohConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohConn").field("ip", &self.ip).finish()
    }
}

#[async_trait]
impl DnsConn for DohConn {
    async fn query(
        &self,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError> {
        // The in-flight cap is a capacity condition, not a connectivity
        // failure: the pool never counts `NoConnections` against the
        // connection or the upstream's health (and answers it by dialing
        // another connection instead).
        let _permit =
            self.cap.clone().try_acquire_owned().map_err(|_| DnsConnError::NoConnections)?;
        // Steady-state peer limit: once the server's SETTINGS are applied,
        // h2-0.4.x parks excess streams *client-side* — no REFUSED_STREAM,
        // and a fresh per-query handle clone's `ready()` is always Ready
        // (it only pends on a handle that itself queued a pending open).
        // The only observable signal left is the peer's advertised
        // concurrency limit vs our in-flight count, so refuse before
        // touching h2 instead of parking into a health-counted Timeout.
        // CAS loop (not fetch_add-then-check) so a simultaneous burst is
        // admitted exactly up to the limit instead of self-colliding into
        // a wasted all-refused wave.
        loop {
            let current = self.in_flight.load(Ordering::Relaxed);
            if current >= self.h2.current_max_send_streams() {
                // A peer advertising zero concurrent streams is refusing all
                // service (a broken or hostile deployment): that is a
                // connectivity-level fault and must surface as the
                // health-counted `Internal` class, so the pool can flip
                // offline and probe for recovery. Capacity above zero stays
                // the capacity class, which never counts against health.
                if self.h2.current_max_send_streams() == 0 {
                    return Err(DnsConnError::Internal(
                        "upstream advertises SETTINGS_MAX_CONCURRENT_STREAMS=0".into(),
                    ));
                }
                return Err(DnsConnError::NoConnections);
            }
            match self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                // Another task admitted itself first — retry with its count.
                Err(_) => continue,
            }
        }
        let _in_flight = InFlightGuard(&self.in_flight);

        let mut message = build_message(query, options);
        // RFC 8484: the HTTP mapping correlates the transaction; a zero id
        // improves HTTP cacheability.
        message.metadata.id = 0;
        let bytes = message.to_vec().map_err(|e| DnsConnError::Internal(e.to_string()))?;

        let request = Request::builder()
            .method("POST")
            .uri(request_uri(&self.server_name, self.port, &self.path))
            .version(Version::HTTP_2)
            .header(CONTENT_TYPE, MIME_APPLICATION_DNS)
            .header(ACCEPT, MIME_APPLICATION_DNS)
            .header(CONTENT_LENGTH, bytes.len())
            .body(())
            .map_err(|e| DnsConnError::Internal(format!("invalid DoH request: {e}")))?;

        // Unlike hickory-net's DoH path, the whole exchange is bounded here
        // so an abandoned or stalled query cannot wedge a stream slot.
        let result = tokio::time::timeout(self.query_timeout, async {
            let h2 = self.h2.clone();
            // A fresh per-query handle clone is always immediately Ready or
            // errors outright: h2 clears the handle's pending-open state on
            // `Clone`, so `ready()` has no Pending path for it (a wedged or
            // saturated peer instead surfaces when awaiting the response —
            // bounded by the query_timeout wrapper around this block). The
            // call is kept for its error path and as a defensive poll.
            let mut h2 =
                h2.ready().await.map_err(|e| DnsConnError::Io(format!("h2 not ready: {e}")))?;
            let (response_future, mut send_stream) =
                h2.send_request(request, false).map_err(map_h2_capacity)?;
            send_stream.send_data(Bytes::from(bytes), true).map_err(map_h2_capacity)?;

            let response = response_future.await.map_err(map_h2_capacity)?;
            let body = read_body(response).await?;
            let message = Message::from_vec(&body)
                .map_err(|e| DnsConnError::Internal(format!("undecodable DoH body: {e}")))?;
            if message.metadata.message_type != MessageType::Response {
                return Err(DnsConnError::Io("DoH body is not a DNS response".into()));
            }
            Ok(message)
        })
        .await;

        match result {
            Ok(Ok(message)) => classify_message(message),
            Ok(Err(e)) => Err(e),
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
        // Drop-based teardown (hickory parity): the h2 connection closes
        // when the last `SendRequest` clone is dropped.
    }
}

/// Builds the DoH request URI. An IPv6 literal `server_name` must be
/// bracketed in the authority (RFC 3986 §3.2.2); an unbracketed `https://`
/// authority containing colons is rejected by the HTTP URI parser, which
/// would make every query fail with `Internal` — and an IPv6 address is a
/// perfectly valid `domain` for TLS/DoH/DoQ upstreams (the config validator
/// accepts IP literals). A non-default port rides in the authority so
/// Host/`:authority`-based virtual-host routing reaches the right server.
fn request_uri(server_name: &str, port: u16, path: &str) -> String {
    let host = match server_name.parse::<IpAddr>() {
        Ok(ip) if ip.is_ipv6() => format!("[{server_name}]"),
        _ => server_name.to_string(),
    };
    if port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{port}{path}")
    }
}

/// Maps h2 exchange errors to the pool's taxonomy. A stream reset with
/// REFUSED_STREAM is the server's capacity signal ("not processed, safe to
/// retry elsewhere") — a capacity condition, not an I/O failure. Everything
/// else stays I/O-class.
fn map_h2_capacity(e: h2::Error) -> DnsConnError {
    if e.reason() == Some(h2::Reason::REFUSED_STREAM) {
        DnsConnError::NoConnections
    } else {
        DnsConnError::Io(format!("h2 exchange failed: {e}"))
    }
}

/// Decrements the connection's in-flight count when a query ends, whatever
/// the exit path (early error returns included).
struct InFlightGuard<'a>(&'a AtomicUsize);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Collects the response body, enforcing the DoH response contract: 2xx
/// status, the DNS content type, a Content-Length match when advertised,
/// and a bounded size (a DNS message cannot exceed 65535 bytes).
async fn read_body(mut response: Response<h2::RecvStream>) -> Result<Vec<u8>, DnsConnError> {
    let content_length = response
        .headers()
        .get(CONTENT_LENGTH)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|e| DnsConnError::Io(format!("bad Content-Length header: {e}")))?
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|e| DnsConnError::Io(format!("bad Content-Length header: {e}")))?;

    // RFC 8484 §4.2.1: non-2xx responses carry no DNS answer.
    if !response.status().is_success() {
        return Err(DnsConnError::Io(format!("DoH returned HTTP {}", response.status())));
    }
    // The content type must be the DNS wire format (when specified).
    if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
        let content_type = content_type
            .to_str()
            .map_err(|e| DnsConnError::Io(format!("bad Content-Type header: {e}")))?;
        if content_type != MIME_APPLICATION_DNS {
            return Err(DnsConnError::Io(format!(
                "unsupported Content-Type '{content_type}' (must be '{MIME_APPLICATION_DNS}')"
            )));
        }
    }

    let mut body = Vec::with_capacity(content_length.unwrap_or(512).clamp(512, 4_096));
    while let Some(partial) = response.body_mut().data().await {
        let partial = partial.map_err(map_h2_capacity)?;
        body.extend_from_slice(&partial);
        // A DNS message is bounded by its 16-bit length fields: a server
        // streaming beyond that is misbehaving (or hostile) and must not
        // be allowed to grow the buffer without limit.
        if body.len() > u16::MAX as usize {
            return Err(DnsConnError::Io("DoH body exceeds the 65535-byte DNS limit".into()));
        }
        if let Some(content_length) = content_length
            && body.len() >= content_length
        {
            break;
        }
    }
    if let Some(content_length) = content_length
        && body.len() != content_length
    {
        return Err(DnsConnError::Io(format!(
            "expected {content_length} body bytes, got {}",
            body.len()
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uri_is_https_with_server_name_and_path() {
        let request = Request::builder()
            .method("POST")
            .uri("https://dns.example.com/dns-query".to_string())
            .version(Version::HTTP_2)
            .body(())
            .unwrap();
        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().authority().unwrap().as_str(), "dns.example.com");
        assert_eq!(request.uri().path(), "/dns-query");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.version(), Version::HTTP_2);
    }

    #[test]
    fn request_uri_passes_hostnames_and_ipv4_through() {
        assert_eq!(
            request_uri("dns.example.com", 443, "/dns-query"),
            "https://dns.example.com/dns-query"
        );
        assert_eq!(request_uri("223.5.5.5", 443, "/dns-query"), "https://223.5.5.5/dns-query");
    }

    #[test]
    fn request_uri_brackets_ipv6_literals() {
        let uri = request_uri("2001:db8::1", 443, "/dns-query");
        assert_eq!(uri, "https://[2001:db8::1]/dns-query");
        // The point of the fix: the URI must actually parse.
        let request = Request::builder().method("POST").uri(uri).body(()).unwrap();
        assert_eq!(request.uri().authority().unwrap().as_str(), "[2001:db8::1]");
        assert_eq!(request.uri().path(), "/dns-query");
    }

    #[test]
    fn request_uri_brackets_ipv6_with_port_style_suffix() {
        let uri = request_uri("::1", 443, "/");
        assert_eq!(uri, "https://[::1]/");
        assert!(Request::builder().uri(uri).body(()).is_ok());
    }

    /// A non-default port rides in the authority (bracketed for IPv6), so
    /// `:authority`-based virtual-host routing reaches the right server.
    #[test]
    fn request_uri_includes_non_default_port() {
        assert_eq!(
            request_uri("dns.example.com", 8443, "/dns-query"),
            "https://dns.example.com:8443/dns-query"
        );
        let uri = request_uri("2001:db8::1", 8053, "/dns-query");
        assert_eq!(uri, "https://[2001:db8::1]:8053/dns-query");
        let request = Request::builder().method("POST").uri(uri).body(()).unwrap();
        assert_eq!(request.uri().authority().unwrap().as_str(), "[2001:db8::1]:8053");
        assert_eq!(request.uri().port_u16(), Some(8053));
    }
}
