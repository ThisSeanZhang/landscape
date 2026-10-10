//! Native quinn-based DoQ (DNS-over-QUIC, RFC 9250) transport.
//!
//! This connector dials quinn directly and implements the same
//! [`DnsConnector`] / [`DnsConn`] traits — the pool logic never notices. The
//! DoQ wire mapping (RFC 9250 §4.2) is trivial: one bidi stream per query, a
//! 2-octet length prefix, and a message id of 0.
//!
//! The socket is still created through the provider's `bind_quic`, so
//! SO_MARK and source-address binding are preserved.

use std::fmt::Debug;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{DnsRequestOptions, Message, Query};
use tokio::sync::Semaphore;

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::upstream::pool_config::{
    PoolConfig, STREAM_CAPACITY_WAIT, keep_alive_interval,
};
use crate::connection::upstream::traits::{DnsConn, DnsConnError, DnsConnector, DnsTransport};

use super::{build_message, classify_message};

/// RFC 9250 §4.1: the DoQ ALPN token.
const DOQ_ALPN: &[u8] = b"doq";

/// Builds the DoQ connector for `addr`, honouring the pool's QUIC tuning
/// (`idle_timeout`, `keep_alive`). `server_name` / `tls_config` are always
/// `Some` for DoQ (see `build_connectors`); missing values surface as a
/// connect-time error.
pub(super) fn connector(
    addr: SocketAddr,
    server_name: Option<Arc<str>>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    provider: MarkRuntimeProvider,
    config: &PoolConfig,
) -> Arc<dyn DnsConnector> {
    let mut transport_config = quinn::TransportConfig::default();
    // DoQ adjustments mirroring hickory-net's `quic_config::transport`.
    transport_config.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);
    // The pool reaps idle connections after `idle_timeout`; the connection's
    // own idle timeout is aligned to it, so a connection that would survive
    // the pool's grace period is still closed by the negotiated timeout
    // instead of wedging. Clamped to quinn's VarInt ceiling so an absurd
    // configured value cannot fail the conversion.
    let idle = config.idle_timeout.min(Duration::from_millis(quinn::VarInt::MAX.into_inner()));
    transport_config.max_idle_timeout(Some(idle.try_into().expect("clamped idle timeout")));
    // Keep-alives (DoQ defaults to on) fire well below the locally
    // configured idle timeout; the negotiated timeout is the minimum of
    // both peers', so a peer advertising a lower value can still reap the
    // connection between keep-alives (see `keep_alive_interval`).
    let keep_alive = config.keep_alive.then(|| keep_alive_interval(config.idle_timeout));
    if let Some(interval) = keep_alive {
        transport_config.keep_alive_interval(Some(interval));
    }

    Arc::new(NativeQuicConnector {
        addr,
        server_name,
        tls_config,
        provider,
        connect_timeout: config.connect_timeout,
        query_timeout: config.query_timeout,
        max_active_requests: config.max_active_requests,
        transport_config: Arc::new(transport_config),
        endpoint: std::sync::OnceLock::new(),
        #[cfg(test)]
        idle_timeout: idle,
        #[cfg(test)]
        keep_alive_interval: keep_alive,
    })
}

/// One connector: dials (and re-dials) DoQ connections to a single endpoint.
/// All connections share one quinn endpoint (one UDP socket per upstream,
/// created lazily on the first connect), which also enables session
/// resumption across re-dials.
#[derive(Debug)]
struct NativeQuicConnector {
    addr: SocketAddr,
    server_name: Option<Arc<str>>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    provider: MarkRuntimeProvider,
    connect_timeout: Duration,
    /// Self-bounds every query exchange (the `DnsConn` contract forbids
    /// blocking indefinitely, even though the pool wraps calls too).
    query_timeout: Duration,
    /// Client-side in-flight cap per connection (mirrors the stream
    /// multiplexer's `max_active_requests`).
    max_active_requests: usize,
    transport_config: Arc<quinn::TransportConfig>,
    /// Shared endpoint, built lazily on the first `connect` (quinn spawns the
    /// endpoint driver task at creation, which requires a running runtime).
    /// Only successful builds are cached: a transient failure (fd exhaustion,
    /// a momentary bind failure) must not poison the connector for its
    /// lifetime, or a DoQ upstream would never recover.
    endpoint: std::sync::OnceLock<Arc<quinn::Endpoint>>,
    /// Test-only introspection of the applied idle timeout.
    #[cfg(test)]
    idle_timeout: Duration,
    /// Test-only introspection of the applied keep-alive cadence.
    #[cfg(test)]
    keep_alive_interval: Option<Duration>,
}

impl NativeQuicConnector {
    /// Builds the shared endpoint: SO_MARK + bind through the provider,
    /// DoQ ALPN, transport tuning, and the default client config.
    fn build_endpoint(&self) -> Result<quinn::Endpoint, io::Error> {
        let Some(tls_config) = &self.tls_config else {
            return Err(io::Error::other("missing TLS config"));
        };

        let socket = self.provider.bind_quic(self.addr)?;

        let mut crypto_config: rustls::ClientConfig = (**tls_config).clone();
        // RFC 9250 §4.1: the connection is identified as DoQ by its ALPN
        // token; only added when the caller left the list empty.
        if crypto_config.alpn_protocols.is_empty() {
            crypto_config.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        }
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)
                .map_err(io::Error::other)?,
        ));
        client_config.transport_config(self.transport_config.clone());

        let mut endpoint_config = quinn::EndpointConfig::default();
        // All DoQ messages are bounded by the 2-octet length field; mirror
        // hickory-net's endpoint tuning.
        endpoint_config
            .max_udp_payload_size(0x45ac)
            .expect("maximum UDP payload size within bounds");

        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(io::Error::other)?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    /// Returns the shared endpoint, building it on first use. Only success is
    /// cached: a failed build can be retried by a later `connect`.
    fn endpoint(&self) -> Result<Arc<quinn::Endpoint>, DnsConnError> {
        if let Some(endpoint) = self.endpoint.get() {
            return Ok(endpoint.clone());
        }
        let endpoint =
            Arc::new(self.build_endpoint().map_err(|e| DnsConnError::Io(e.to_string()))?);
        match self.endpoint.set(endpoint.clone()) {
            Ok(()) => Ok(endpoint),
            // A concurrent build won the cache race: drop our duplicate (its
            // socket closes with the local Arc) and share the winner, so at
            // most one endpoint driver and bound socket live per connector.
            Err(_) => Ok(self.endpoint.get().expect("race loser: winner must be set").clone()),
        }
    }
}

#[async_trait]
impl DnsConnector for NativeQuicConnector {
    async fn connect(&self) -> Result<Arc<dyn DnsConn>, DnsConnError> {
        let endpoint = self.endpoint()?;
        let Some(server_name) = &self.server_name else {
            return Err(DnsConnError::Internal("missing DoQ server name".into()));
        };

        let connecting = endpoint
            .connect(self.addr, server_name)
            .map_err(|e| DnsConnError::Io(e.to_string()))?;
        let connection = tokio::time::timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| DnsConnError::Timeout)?
            .map_err(map_conn_error)?;

        Ok(Arc::new(NativeQuicConn {
            connection,
            ip: self.addr.ip(),
            query_timeout: self.query_timeout,
            cap: Arc::new(Semaphore::new(self.max_active_requests.max(1))),
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
        Some((self.addr, "Quic".to_string()))
    }

    /// Test-only QUIC transport introspection: the applied idle timeout and
    /// keep-alive cadence.
    #[cfg(test)]
    fn test_quic_transport(&self) -> Option<(Duration, Option<Duration>)> {
        Some((self.idle_timeout, self.keep_alive_interval))
    }
}

/// One established DoQ connection.
struct NativeQuicConn {
    connection: quinn::Connection,
    ip: IpAddr,
    query_timeout: Duration,
    /// Client-side in-flight cap. Saturation must surface as the capacity
    /// class (`NoConnections`) exactly like the stream multiplexer: a
    /// silently queued `open_bi` would instead age into a spurious
    /// `Timeout`, which the pool counts against the upstream's health — a
    /// healthy upstream under burst load would flip offline.
    cap: Arc<Semaphore>,
}

impl std::fmt::Debug for NativeQuicConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeQuicConn").field("ip", &self.ip).finish()
    }
}

#[async_trait]
impl DnsConn for NativeQuicConn {
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

        // RFC 9250 §4.2: one bidi stream per query; the message id MUST be 0
        // (the stream mapping correlates query and response). A peer
        // advertising a bidi-stream limit below our own cap parks excess
        // callers inside `open_bi`; the bounded wait keeps that a capacity
        // condition (NoConnections — the pool dials around it) instead of
        // aging into a health-counted Timeout. Like every other transport,
        // the whole exchange is self-bounded by `query_timeout` (the
        // `DnsConn` contract forbids blocking indefinitely, even though
        // the pool wraps calls in its own budget too).
        let result = tokio::time::timeout(self.query_timeout, async {
            let (mut send_stream, mut recv_stream) =
                match tokio::time::timeout(STREAM_CAPACITY_WAIT, self.connection.open_bi()).await {
                    Ok(open) => open.map_err(map_conn_error)?,
                    Err(_) => return Err(DnsConnError::NoConnections),
                };

            let mut message = build_message(query, options);
            message.metadata.id = 0;
            let bytes = message.to_vec().map_err(|e| DnsConnError::Internal(e.to_string()))?;
            let len = u16::try_from(bytes.len()).map_err(|_| {
                DnsConnError::Internal("DoQ message exceeds the 65535-byte limit".into())
            })?;

            // All DoQ messages are a 2-octet length field followed by the message
            // content, exactly like the DNS-over-TCP framing (RFC 1035).
            let mut frame = Vec::with_capacity(2 + bytes.len());
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(&bytes);
            send_stream.write_all(&frame).await.map_err(map_write_error)?;
            send_stream.finish().map_err(|e| DnsConnError::Io(e.to_string()))?;

            let mut len = [0u8; 2];
            recv_stream.read_exact(&mut len).await.map_err(map_read_error)?;
            let len = u16::from_be_bytes(len) as usize;
            let mut body = vec![0u8; len];
            recv_stream.read_exact(&mut body).await.map_err(map_read_error)?;

            let message =
                Message::from_vec(&body).map_err(|e| DnsConnError::Internal(e.to_string()))?;
            // RFC 9250 §4.2.1: the response id MUST be 0 too.
            if message.id != 0 {
                return Err(DnsConnError::Io(format!(
                    "DoQ response message id must be 0, got {}",
                    message.id
                )));
            }
            classify_message(message)
        })
        .await;

        match result {
            Ok(outcome) => outcome,
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
        self.connection.close(quinn::VarInt::from_u32(0), b"Shutdown");
    }
}

/// Maps a quinn connection error to the pool's taxonomy. An idle/keep-alive
/// timeout proves the connection is dead (transient); a certificate-class
/// TLS alert (untrusted/expired certificate) is permanent and fails fast;
/// everything else is a plain I/O failure.
fn map_conn_error(e: quinn::ConnectionError) -> DnsConnError {
    if matches!(e, quinn::ConnectionError::TimedOut) {
        return DnsConnError::Timeout;
    }
    // quinn reports handshake failures as a crypto-class transport error
    // (code 0x100 | TLS alert). Certificate-class alerts mean the
    // certificate is untrusted/expired: permanent, never counted as
    // transient connectivity.
    if let quinn::ConnectionError::TransportError(te) = &e
        && is_cert_class_transport_code(u64::from(te.code))
    {
        return DnsConnError::Tls(e.to_string());
    }
    DnsConnError::Io(e.to_string())
}

/// True for a crypto-class transport error code (0x100 | TLS alert, RFC 8446
/// §6.2) whose alert is a certificate-class failure (untrusted, expired, ...).
fn is_cert_class_transport_code(code: u64) -> bool {
    (0x100..0x200).contains(&code) && is_cert_alert(code as u8)
}

/// TLS alert codes of certificate-class failures.
fn is_cert_alert(alert: u8) -> bool {
    matches!(
        alert,
        42 | 43 | 44 | 45 | 46 | 48 | 49 // bad_certificate, unsupported_certificate,
                                         // certificate_revoked, certificate_expired,
                                         // certificate_unknown, unknown_ca, access_denied
    )
}

/// Maps a quinn write error, surfacing the connection-level timeout when the
/// connection was lost to one.
fn map_write_error(e: quinn::WriteError) -> DnsConnError {
    match e {
        quinn::WriteError::ConnectionLost(inner) => map_conn_error(inner),
        other => DnsConnError::Io(other.to_string()),
    }
}

/// Maps a quinn read error, surfacing the connection-level timeout when the
/// connection was lost to one.
fn map_read_error(e: quinn::ReadExactError) -> DnsConnError {
    match e {
        quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(inner)) => {
            map_conn_error(inner)
        }
        other => DnsConnError::Io(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An idle/keep-alive timeout is a *transient* connectivity failure: it
    /// proves the connection is dead and counts towards connection retirement
    /// and the upstream offline flip (unlike the capacity-class errors).
    #[test]
    fn map_conn_error_idle_timeout_is_transient() {
        assert!(matches!(map_conn_error(quinn::ConnectionError::TimedOut), DnsConnError::Timeout));
    }

    /// Every other connection-level failure is a plain I/O error.
    #[test]
    fn map_conn_error_other_failures_are_io() {
        for e in [
            quinn::ConnectionError::LocallyClosed,
            quinn::ConnectionError::Reset,
            quinn::ConnectionError::VersionMismatch,
        ] {
            assert!(matches!(map_conn_error(e), DnsConnError::Io(_)));
        }
    }

    /// A certificate-class TLS alert (untrusted/expired certificate) is
    /// permanent: it maps to the `Tls` class so the pool fails fast and
    /// never counts it towards connection retirement or the offline flip.
    #[test]
    fn cert_class_transport_codes_are_permanent_tls_class() {
        for alert in [42, 43, 44, 45, 46, 48, 49] {
            assert!(
                is_cert_class_transport_code(0x100 | alert),
                "alert {alert} should be certificate-class"
            );
        }
    }

    /// A handshake/other crypto-class failure is transient (server-side
    /// config can change), not a permanent certificate problem.
    #[test]
    fn non_cert_crypto_codes_stay_transient() {
        for code in [
            0x100 | 40, // handshake_failure
            0x100 | 51, // decrypt_error
            0x100 | 47, // illegal_parameter
            0x200,      // not a crypto-class code
            0x00,       // not a crypto-class code
        ] {
            assert!(!is_cert_class_transport_code(code), "code {code:#x} should not be TLS-class");
        }
    }

    /// A write failure that surfaces the connection-level timeout keeps the
    /// timeout classification (so a peer that idles out mid-query is counted
    /// as a connectivity failure, not an I/O hiccup).
    #[test]
    fn map_write_error_surfaces_connection_timeout() {
        assert!(matches!(
            map_write_error(quinn::WriteError::ConnectionLost(quinn::ConnectionError::TimedOut)),
            DnsConnError::Timeout
        ));
        assert!(matches!(map_write_error(quinn::WriteError::ClosedStream), DnsConnError::Io(_)));
    }

    /// Same for reads: the idle-timeout loss surfaces as `Timeout`, other
    /// stream/connection failures as `Io`.
    #[test]
    fn map_read_error_surfaces_connection_timeout() {
        assert!(matches!(
            map_read_error(quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(
                quinn::ConnectionError::TimedOut
            ))),
            DnsConnError::Timeout
        ));
        assert!(matches!(
            map_read_error(quinn::ReadExactError::FinishedEarly(0)),
            DnsConnError::Io(_)
        ));
    }
}
