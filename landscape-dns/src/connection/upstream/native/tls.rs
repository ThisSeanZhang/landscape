//! TLS handshake helper shared by DoT and DoH.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;

use crate::connection::provider::MarkRuntimeProvider;
use crate::connection::upstream::traits::DnsConnError;

/// Connects a marked TCP socket and performs the TLS handshake, all within
/// one shared `connect_timeout` budget: a black-holed handshake (SYN-ACK
/// reachable, TLS packets dropped) consumes what is left of the budget
/// instead of doubling the worst-case dial latency past the pool's
/// lookup-level deadline math.
pub(super) async fn connect_tls(
    provider: &MarkRuntimeProvider,
    addr: SocketAddr,
    server_name: &str,
    tls_config: Arc<rustls::ClientConfig>,
    connect_timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DnsConnError> {
    let server_name = ServerName::try_from(server_name.to_owned()).map_err(
        |e: rustls::pki_types::InvalidDnsNameError| DnsConnError::Internal(e.to_string()),
    )?;
    let deadline = tokio::time::Instant::now() + connect_timeout;
    let tcp = provider
        .connect_tcp(addr, Some(connect_timeout))
        .await
        .map_err(|e| DnsConnError::Io(e.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    tokio::time::timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| DnsConnError::Timeout)?
    .map_err(classify_tls_error)
}

/// Classifies a TLS handshake error: certificate-class and ALPN failures are
/// permanent (`Tls` — retrying cannot succeed, so the pool fails fast and
/// never counts them as transient connectivity), everything else is a plain
/// connection error.
pub(super) fn classify_tls_error(e: io::Error) -> DnsConnError {
    let Some(rustls_error) = e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) else {
        return DnsConnError::Io(e.to_string());
    };
    match rustls_error {
        rustls::Error::InvalidCertificate(_) => DnsConnError::Tls(e.to_string()),
        rustls::Error::NoApplicationProtocol => DnsConnError::Tls(format!(
            "ALPN negotiation failed (the upstream does not speak the required protocol): {e}"
        )),
        other => DnsConnError::Io(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_errors_are_permanent_tls_class() {
        let inner = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let e = io::Error::new(io::ErrorKind::InvalidData, inner);
        assert!(matches!(classify_tls_error(e), DnsConnError::Tls(_)));
    }

    #[test]
    fn alpn_mismatch_is_permanent_tls_class() {
        let e = io::Error::other(rustls::Error::NoApplicationProtocol);
        assert!(matches!(classify_tls_error(e), DnsConnError::Tls(_)));
    }

    #[test]
    fn plain_io_errors_stay_transient() {
        let e = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert!(matches!(classify_tls_error(e), DnsConnError::Io(_)));
    }

    #[test]
    fn non_cert_rustls_errors_stay_transient() {
        let e = io::Error::other(rustls::Error::HandshakeNotComplete);
        assert!(matches!(classify_tls_error(e), DnsConnError::Io(_)));
    }
}
