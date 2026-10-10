//! Protocol-stack boundary of the upstream connection pool.
//!
//! The pool (lifecycle, warm-up, selection, maintenance, health) only ever
//! sees [`DnsConnector`] / [`DnsConn`] and the plain wire types below. The
//! native transports (UDP, the stream multiplexer, DoH, DoQ) implement
//! these traits; any future stack swaps in without touching the pool
//! logic.

use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Message, Query, ResponseCode};
use hickory_proto::rr::Record;

/// Transport family of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DnsTransport {
    /// Stateless datagram transport (UDP). A single connection multiplexes
    /// all queries; no handshake to amortize.
    Udp,
    /// Stateful stream transport (TCP/TLS/DoH/DoQ). Connections are pooled
    /// and reused to amortize the (expensive) handshake.
    Stream,
}

/// Errors surfaced by a single connection query.
#[derive(Debug, Clone)]
pub(crate) enum DnsConnError {
    /// No response within the attempt budget.
    Timeout,
    /// Connection-level I/O failure (connect refused/reset).
    Io(String),
    /// No usable connection or connection config exists.
    NoConnections,
    /// Upstream answered with an explicit error code. When the answer was a
    /// negative one (NXDomain/NoError without records), the SOA record from
    /// the authority section rides along so the caller can honour RFC 2308
    /// negative caching; `None` when the code came from a path that carried
    /// no SOA.
    Protocol(ResponseCode, Option<Box<Record>>),
    /// A permanent TLS failure (certificate verification, handshake policy).
    /// Retrying cannot succeed, so callers fail fast and never count it as a
    /// transient connectivity failure.
    Tls(String),
    /// Anything else.
    Internal(String),
}

impl std::fmt::Display for DnsConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsConnError::Timeout => write!(f, "query timed out"),
            DnsConnError::Io(e) => write!(f, "connection error: {e}"),
            DnsConnError::NoConnections => write!(f, "no usable connections"),
            DnsConnError::Protocol(code, _) => write!(f, "upstream answered {code}"),
            DnsConnError::Tls(e) => write!(f, "TLS failure: {e}"),
            DnsConnError::Internal(e) => write!(f, "internal error: {e}"),
        }
    }
}

/// A single established connection to an upstream endpoint.
#[async_trait]
pub(crate) trait DnsConn: Send + Sync + Debug {
    /// Sends one query and awaits the response.
    ///
    /// The pool enforces the per-attempt budget (a `tokio::time::timeout`
    /// wrapper in `UpstreamPool::query_once`), so this must never block
    /// indefinitely on its own; the underlying hickory streams additionally
    /// apply their own `query_timeout` so an abandoned query cannot wedge the
    /// multiplexer.
    async fn query(
        &self,
        query: &Query,
        options: &DnsRequestOptions,
    ) -> Result<Message, DnsConnError>;

    fn transport(&self) -> DnsTransport;

    fn ip(&self) -> IpAddr;

    /// Closes the connection and releases its resources.
    fn shutdown(&self);
}

/// Builds connections to one upstream endpoint (ip + protocol).
///
/// Connection establishment is lazy: nothing is dialed until `connect()` is
/// called (by the pool's maintenance warm-up or the first query).
#[async_trait]
pub(crate) trait DnsConnector: Send + Sync + Debug {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError>;

    fn transport(&self) -> DnsTransport;

    fn ip(&self) -> IpAddr;

    /// Test-only endpoint introspection (topology assertions); `None` for
    /// connectors that do not expose their endpoint. The string is the
    /// connector's protocol tag (`"Udp"`, `"Tcp"`, `"Tls"`, `"Https"`,
    /// `"Quic"`).
    #[cfg(test)]
    fn test_endpoint(&self) -> Option<(std::net::SocketAddr, String)> {
        None
    }

    /// Test-only TLS config introspection (e.g. the DoT SNI pin).
    #[cfg(test)]
    fn test_tls_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        None
    }

    /// Test-only QUIC transport introspection: the applied idle timeout and
    /// keep-alive cadence. `None` for non-QUIC connectors.
    #[cfg(test)]
    fn test_quic_transport(&self) -> Option<(std::time::Duration, Option<std::time::Duration>)> {
        None
    }
}
